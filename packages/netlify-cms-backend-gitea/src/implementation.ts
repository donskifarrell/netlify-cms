import trimStart from 'lodash/trimStart';
import semaphore, { Semaphore } from 'semaphore';
import { trim } from 'lodash';
import { stripIndent } from 'common-tags';
import {
  EditorialWorkflowError,
  CURSOR_COMPATIBILITY_SYMBOL,
  basename,
  Entry,
  AssetProxy,
  PersistOptions,
  Cursor,
  Implementation,
  DisplayURL,
  entriesByFolder,
  entriesByFiles,
  getMediaDisplayURL,
  getMediaAsBlob,
  User,
  Credentials,
  Config,
  ImplementationFile,
  unpublishedEntries,
  getPreviewStatus,
  UnpublishedEntryMediaFile,
  asyncLock,
  AsyncLock,
  runWithLock,
  getBlobSHA,
  blobToFileObj,
  contentKeyFromBranch,
  generateContentKey,
  localForage,
  allEntriesByFolder,
  filterByExtension,
  branchFromContentKey,
} from 'netlify-cms-lib-util';
import AuthenticationPage from './AuthenticationPage';
import API, { API_NAME } from './API';

const MAX_CONCURRENT_DOWNLOADS = 10;

export default class Gitea implements Implementation {
  lock: AsyncLock;
  api: API | null;
  options: {
    proxied: boolean;
    API: API | null;
    initialWorkflowStatus: string;
  };
  repo: string;
  branch: string;
  apiRoot: string;
  token: string | null;
  squashMerges: boolean;
  cmsLabelPrefix: string;
  approverToken?: string;
  mediaFolder: string;
  previewContext: string;
  commitMessages?: {
    create?: string;
    update?: string;
    delete?: string;
    uploadMedia?: string;
    deleteMedia?: string;
    openAuthoring?: string;
    merge?: string;
  };

  _mediaDisplayURLSem?: Semaphore;

  constructor(config: Config, options = {}) {
    this.options = {
      proxied: false,
      API: null,
      initialWorkflowStatus: '',
      ...options,
    };

    if (
      !this.options.proxied &&
      (config.backend.repo === null || config.backend.repo === undefined)
    ) {
      throw new Error('The Gitea backend needs a "repo" in the backend configuration.');
    }

    this.api = this.options.API || null;

    this.repo = config.backend.repo || '';
    this.branch = config.backend.branch || 'master';
    this.apiRoot = config.backend.api_root || 'https://gitea.com/api/v1';
    this.token = '';
    this.squashMerges = config.backend.squash_merges || false;
    this.approverToken = config.backend.approver_token || '';
    this.cmsLabelPrefix = config.backend.cms_label_prefix || '';
    this.mediaFolder = config.media_folder;
    this.previewContext = config.backend.preview_context || '';
    this.commitMessages = config.backend.commit_messages
    this.lock = asyncLock();
  }

  isGitBackend() {
    return true;
  }

  async status() {
    const auth =
      (await this.api
        ?.user()
        .then(user => !!user)
        .catch(e => {
          console.warn('Failed getting Gitea user', e);
          return false;
        })) || false;

    return { auth: { status: auth }, api: { status: true, statusPage: '' } };
  }

  authComponent() {
    return AuthenticationPage;
  }

  restoreUser(user: User) {
    return this.authenticate(user);
  }

  async authenticate(state: Credentials) {
    this.token = state.token as string;
    this.api = new API({
      token: this.token,
      branch: this.branch,
      repo: this.repo,
      apiRoot: this.apiRoot,
      squashMerges: this.squashMerges,
      approverToken: this.approverToken,
      cmsLabelPrefix: this.cmsLabelPrefix,
      initialWorkflowStatus: this.options.initialWorkflowStatus,
      commitMessages: this.commitMessages,
    });
    const user = await this.api.user();
    const isCollab = await this.api.hasWriteAccess().catch((error: Error) => {
      error.message = stripIndent`
        Repo "${this.repo}" not found.

        Please ensure the repo information is spelled correctly.

        If the repo is private, make sure you're logged into a Gitea account with access.
      `;
      throw error;
    });

    // Unauthorized user
    if (!isCollab) {
      throw new Error('Your Gitea user account does not have access to this repo.');
    }

    // Authorized user
    return { ...user, login: user.username, token: state.token as string };
  }

  async logout() {
    this.token = null;
    return;
  }

  getToken() {
    return Promise.resolve(this.token);
  }

  filterFile(
    folder: string,
    file: { path: string; name: string },
    extension: string,
    depth: number,
  ) {
    // gitea paths include the root folder
    const fileFolder = trim(file.path.split(folder)[1] || '/', '/');
    return filterByExtension(file, extension) && fileFolder.split('/').length <= depth;
  }

  async entriesByFolder(folder: string, extension: string, depth: number) {
    console.log("call: entriesByFolder ")
    let cursor: Cursor;

    const listFiles = () =>
      this.api!.listFiles(folder, depth > 1).then(({ files, cursor: c }) => {

        cursor = c.mergeMeta({ folder, extension, depth });
        return files.filter(file => this.filterFile(folder, file, extension, depth));
      });

    const files = await entriesByFolder(
      listFiles,
      this.api!.readFile.bind(this.api!),
      this.api!.readFileMetadata.bind(this.api),
      API_NAME,
    );
    // eslint-disable-next-line @typescript-eslint/ban-ts-ignore
    // @ts-ignore
    files[CURSOR_COMPATIBILITY_SYMBOL] = cursor;
    return files;
  }

  async listAllFiles(folder: string, extension: string, depth: number) {
    const files = await this.api!.listAllFiles(folder, depth > 1);

    const filtered = files.filter(file => this.filterFile(folder, file, extension, depth));
    return filtered;
  }

  async allEntriesByFolder(folder: string, extension: string, depth: number) {
    console.log("call: allEntriesByFolder", folder, extension, depth);
    const files = await allEntriesByFolder({
      listAllFiles: () => this.listAllFiles(folder, extension, depth),
      readFile: this.api!.readFile.bind(this.api!),
      readFileMetadata: this.api!.readFileMetadata.bind(this.api),
      apiName: API_NAME,
      branch: this.branch,
      localForage,
      folder,
      extension,
      depth,
      getDefaultBranch: () =>
        this.api!.getDefaultBranch().then(b => ({ name: b.name, sha: b.commit.id })),
      isShaExistsInBranch: this.api!.isShaExistsInBranch.bind(this.api!),
      getDifferences: (index) => this.api!.getPullDifferences(index),
      getFileId: path => this.api!.getFileId(path, this.branch),
      filterFile: file => this.filterFile(folder, file, extension, depth),
    });
    return files;
  }

  entriesByFiles(files: ImplementationFile[]) {
    console.log("call: entriesByFiles");
    return entriesByFiles(
      files,
      this.api!.readFile.bind(this.api!),
      this.api!.readFileMetadata.bind(this.api),
      API_NAME,
    );
  }

  // Fetches a single entry.
  getEntry(path: string) {
    console.log("call: getEntry");
    return this.api!.readFile(path).then(data => {
      return {
        file: { path, id: null },
        data: data as string,
      }
    });
  }

  getMedia(mediaFolder = this.mediaFolder) {
    console.log("call: getMedia")
    return this.api!.listAllFiles(mediaFolder).then(files =>
      files.map(({ id, name, path }) => {
        return { id, name, path, displayURL: { id, name, path } };
      }),
    );
  }

  getMediaDisplayURL(displayURL: DisplayURL) {
    console.log("call: getMediaDisplayURL ")

    this._mediaDisplayURLSem = this._mediaDisplayURLSem || semaphore(MAX_CONCURRENT_DOWNLOADS);
    return getMediaDisplayURL(
      displayURL,
      this.api!.readFile.bind(this.api!),
      this._mediaDisplayURLSem,
    );
  }

  async getMediaFile(path: string) {
    console.log("call: getMediaFile ")
    const name = basename(path);
    const blob = await getMediaAsBlob(path, null, this.api!.readFile.bind(this.api!));
    const fileObj = blobToFileObj(name, blob);
    const url = URL.createObjectURL(fileObj);
    const id = await getBlobSHA(blob);

    return {
      id,
      displayURL: url,
      path,
      name,
      size: fileObj.size,
      file: fileObj,
      url,
    };
  }

  async persistEntry(entry: Entry, options: PersistOptions) {
    console.log("call: persistEntry")
    // persistEntry is a transactional operation
    return runWithLock(
      this.lock,
      () => this.api!.persistFiles(entry.dataFiles, entry.assets, options),
      'Failed to acquire persist entry lock',
    );
  }

  async persistMedia(mediaFile: AssetProxy, options: PersistOptions) {
    const fileObj = mediaFile.fileObj as File;
    console.log("call: persistMedia")
    const [id] = await Promise.all([
      getBlobSHA(fileObj),
      this.api!.persistFiles([], [mediaFile], options),
    ]);

    const { path } = mediaFile;
    const url = URL.createObjectURL(fileObj);

    return {
      displayURL: url,
      path: trimStart(path, '/'),
      name: fileObj!.name,
      size: fileObj!.size,
      file: fileObj,
      url,
      id,
    };
  }

  async deleteFiles(paths: string[], commitMessage: string) {
    return await this.api!.deleteFiles(paths, commitMessage);
  }

  traverseCursor(cursor: Cursor, action: string) {
    return this.api!.traverseCursor(cursor, action).then(async ({ entries, cursor: newCursor }) => {
      const [folder, depth, extension] = [
        cursor.meta?.get('folder') as string,
        cursor.meta?.get('depth') as number,
        cursor.meta?.get('extension') as string,
      ];
      if (folder && depth && extension) {
        entries = entries.filter(f => this.filterFile(folder, f, extension, depth));
        newCursor = newCursor.mergeMeta({ folder, extension, depth });
      }
      const entriesWithData = await entriesByFiles(
        entries,
        this.api!.readFile.bind(this.api!),
        this.api!.readFileMetadata.bind(this.api)!,
        API_NAME,
      );
      return {
        entries: entriesWithData,
        cursor: newCursor,
      };
    });
  }

  loadMediaFile(branch: string, file: UnpublishedEntryMediaFile) {
    console.log("call: loadmediafile ")
    const readFile = (
      path: string,
      id: string | null | undefined,
      { parseText }: { parseText: boolean },
    ) => this.api!.readFile(path, id, { branch, parseText });

    return getMediaAsBlob(file.path, null, readFile).then(blob => {
      const name = basename(file.path);
      const fileObj = blobToFileObj(name, blob);
      return {
        id: file.path,
        displayURL: URL.createObjectURL(fileObj),
        path: file.path,
        name,
        size: fileObj.size,
        file: fileObj,
      };
    });
  }

  async loadEntryMediaFiles(branch: string, files: UnpublishedEntryMediaFile[]) {
    console.log("call: loadEntryMediaFiles")
    const mediaFiles = await Promise.all(files.map(file => this.loadMediaFile(branch, file)));

    return mediaFiles;
  }

  async unpublishedEntries() {
    const listEntriesKeys = () =>
      this.api!.listUnpublishedBranches().then(branches =>
        branches.map(branch => contentKeyFromBranch(branch)),
      );

    const ids = await unpublishedEntries(listEntriesKeys);
    return ids;
  }

  async unpublishedEntry({
    id,
    collection,
    slug,
  }: {
    id?: string;
    collection?: string;
    slug?: string;
  }) {
    console.log("call: unpublishedEntry")
    let entryFile;
    if (id) {
      // UnpublishedEntryData is already existing
      entryFile = await this.api!.retrieveUnpublishedEntryData(id);
    } else if (collection && slug) {
      // UnpublishedEntryData is newly created
      const entryId = generateContentKey(collection, slug);
      entryFile = await this.api!.retrieveUnpublishedEntryData(entryId);
    } else {
      throw new Error('Missing unpublished entry id or collection and slug');
    }

    if (!entryFile) {
      return Promise.reject(
        new EditorialWorkflowError('content is not under editorial workflow', true),
      );
    }

    return entryFile
  }

  getBranch(collection: string, slug: string) {
    const contentKey = generateContentKey(collection, slug);
    const branch = branchFromContentKey(contentKey);
    return branch;
  }

  async unpublishedEntryDataFile(collection: string, slug: string, path: string, id: string) {
    const branch = this.getBranch(collection, slug);
    console.log("call: unpublishedEntryDataFile ", branch)
    const data = (await this.api!.readFile(path, id, { branch })) as string;
    return data;
  }

  async unpublishedEntryMediaFile(collection: string, slug: string, path: string, id: string) {
    const branch = this.getBranch(collection, slug);
    console.log("call: unpublishedEntryMediaFile", branch)
    const mediaFile = await this.loadMediaFile(branch, { path, id });
    return mediaFile;
  }

  async updateUnpublishedEntryStatus(collection: string, slug: string, newStatus: string) {
    console.log("call: updateUnpublishedEntryStatus", newStatus)

    // updateUnpublishedEntryStatus is a transactional operation
    return runWithLock(
      this.lock,
      () => this.api!.updateUnpublishedEntryStatus(collection, slug, newStatus),
      'Failed to acquire update entry status lock',
    );
  }

  async deleteUnpublishedEntry(collection: string, slug: string) {
    // deleteUnpublishedEntry is a transactional operation
    return runWithLock(
      this.lock,
      () => this.api!.deleteUnpublishedEntry(collection, slug),
      'Failed to acquire delete entry lock',
    );
  }

  async publishUnpublishedEntry(collection: string, slug: string) {
    // publishUnpublishedEntry is a transactional operation
    return runWithLock(
      this.lock,
      () => this.api!.publishUnpublishedEntry(collection, slug),
      'Failed to acquire publish entry lock',
    );
  }

  async getDeployPreview(collection: string, slug: string) {
    try {
      const statuses = await this.api!.getStatuses(collection, slug);
      const deployStatus = getPreviewStatus(statuses, this.previewContext);

      if (deployStatus) {
        const { target_url: url, state } = deployStatus;
        return { url, status: state };
      } else {
        return null;
      }
    } catch (e) {
      return null;
    }
  }
}
