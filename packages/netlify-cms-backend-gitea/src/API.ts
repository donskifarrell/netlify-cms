import {
  localForage,
  parseLinkHeader,
  unsentRequest,
  then,
  APIError,
  Cursor,
  ApiRequest,
  DataFile,
  AssetProxy,
  PersistOptions,
  readFile,
  CMS_BRANCH_PREFIX,
  generateContentKey,
  isCMSLabel,
  EditorialWorkflowError,
  labelToStatus,
  statusToLabel,
  DEFAULT_PR_BODY,
  MERGE_COMMIT_MESSAGE,
  responseParser,
  PreviewState,
  parseContentKey,
  branchFromContentKey,
  requestWithBackoff,
  readFileMetadata,
  FetchError,
  throwOnConflictingBranches,
} from 'netlify-cms-lib-util';
import gd from 'gitdiff-parser';
import { Base64 } from 'js-base64';
import { Map } from 'immutable';
import { flow, partial, pull, result, trimStart } from 'lodash';
import { dirname } from 'path';
import { func } from 'prop-types';
import { ContextReplacementPlugin } from 'webpack';
import { parse } from '@babel/core';

export const API_NAME = 'Gitea';
const APPLICATION_JSON = 'application/json; charset=utf-8';

export interface Config {
  apiRoot?: string;
  token?: string;
  branch?: string;
  repo?: string;
  squashMerges: boolean;
  initialWorkflowStatus: string;
  cmsLabelPrefix: string;
}

export interface CommitAuthor {
  name: string;
  email: string;
}

enum CommitAction {
  CREATE = 'create',
  DELETE = 'delete',
  MOVE = 'move',
  UPDATE = 'update',
}

type CommitItem = {
  base64Content?: string;
  path: string;
  oldPath?: string;
  action: CommitAction;
  sha?: string;
};

// ContentsResponse contains information about a repo's entry's (dir, file, symlink, submodule) metadata and content
type GiteaContentsResponse = {
  name: string;
  path: string;
  sha: string;
  content: string;
  type?: string;
  size?: BigInteger;
  encoding?: string;
  target?: string;
  url?: string;
  html_url?: string;
  git_url?: string;
  download_url?: string;
  submodule_git_url?: string;
  links?: string;
}



interface CommitsParams {
  commit_message: string;
  branch: string;
  author_name?: string;
  author_email?: string;
  actions?: {
    action: string;
    file_path: string;
    previous_path?: string;
    content?: string;
    encoding?: string;
  }[];
}

type GiteaCommitDiff = {
  diff: string;
  new_path: string;
  old_path: string;
  new_file: boolean;
  renamed_file: boolean;
  deleted_file: boolean;
};

enum GiteaCommitStatuses {
  Pending = 'pending',
  Running = 'running',
  Success = 'success',
  Failed = 'failed',
  Canceled = 'canceled',
}

type GiteaCommitStatus = {
  status: GiteaCommitStatuses;
  name: string;
  author: {
    username: string;
    name: string;
  };
  description: null;
  sha: string;
  ref: string;
  target_url: string;
};

type GiteaMergeRebase = {
  rebase_in_progress: boolean;
  merge_error: string;
};

type GiteaMergePullRequestOption = {
  MergeTitleField: string;
  MergeMessageField: string;
  Do: string;
}

// PRBranchInfo information about a branch
type PRBranchInfo = {
  label: string;
  ref: string;
  sha: string;
  repo_id: BigInt;
  repository: any;
}

// PullRequest represents a pull request
type GiteaPullRequest = {
  id: BigInt;
  url: string;
  number: BigInt;
  user: any;
  title: string;
  body: string;
  labels: any;
  milestone: any;
  assignee: any;
  assignees: any;
  state: any;
  is_locked: boolean;
  comments: BigInt;

  html_url: string;
  diff_url: string;
  patch_url: string;

  merged: boolean;
  merged_at: Date;
  merged_commit_sha: string;
  merged_by: any;

  base: PRBranchInfo;
  head: PRBranchInfo;
  merge_base: string;

  due_date: Date;
  created_at: Date;
  updated_at: Date;
  closed_at: Date;
}
// GiteaEditPullRequestOption represents a pull request
type GiteaEditPullRequestOption = {
  title?: string;
  body?: string;
  base?: PRBranchInfo;
  assignee?: any;
  assignees?: any;
  milestone?: any;
  labels?: any;
  state?: any;
  due_date?: Date;
}

type GiteaCreateLabelOption = {
  color?: string;
  description: string;
  name: string;
}

type DeleteEntry = {
  path: string;
  action: CommitAction.DELETE;
};

// GiteaListPullRequestsOptions options for listing pull requests
type GiteaListPullRequestsOptions = {
  state?: any;
  // oldest, recentupdate, leastupdate, mostcomment, leastcomment, priority
  sort?: string;
  milestone?: BigInt;
}

type GiteaCreatePullRequestOption = {
  head: string; // target origin/branch
  base: string; // source fork/branch
  title: string;
  body: string;
  assignee?: string;
  assignees?: string[];
  milestone?: BigInt64Array;
  labels?: any;
  deadline?: Date;
};

// GiteaLabel a label to an issue or a pr
type GiteaLabel = {
  id: BigInt;
  name: string;
  // example: 00aabb
  color: string;
  description: string;
  url: string;
}

type GiteaCreateBranchOption = {
  new_branch_name: string;
  old_branch_name: string;
};

type GiteaRepo = {
  permissions: {
    admin: boolean,
    pull: boolean,
    push: boolean,
  };
};

type GiteaIdentity = {
  email: string;
  name: string;
}

// CommitDateOptions store dates for GIT_AUTHOR_DATE and GIT_COMMITTER_DATE
type GiteaCommitDateOptions = {
  author: Date;
  committer: Date;
}

// File
type GiteaFileOption = {
  message?: string;
  branch?: string;
  new_branch?: string;
  author?: GiteaIdentity;
  committer?: GiteaIdentity;
  dates?: GiteaCommitDateOptions;
  signoff: boolean;
};

type GiteaCreateFileOption = {
  content: string;
  // FileOptions
  message?: string;
  branch?: string;
  new_branch?: string;
  author?: GiteaIdentity;
  committer?: GiteaIdentity;
  dates?: GiteaCommitDateOptions;
  signoff: boolean;
};

type GiteaUpdateFileOption = {
  sha: string;
  content: string;
  from_path?: string;
  // FileOptions
  message?: string;
  branch?: string;
  new_branch?: string;
  author?: GiteaIdentity;
  committer?: GiteaIdentity;
  dates?: GiteaCommitDateOptions;
  signoff: boolean;
};

type GiteaDeleteFileOption = {
  sha: string;
  // FileOptions
  message?: string;
  branch?: string;
  new_branch?: string;
  author?: GiteaIdentity;
  committer?: GiteaIdentity;
  dates?: GiteaCommitDateOptions;
  signoff: boolean;
};

// PayloadUser represents the author or committer of a commit
type PayloadUser = {
  // Full name of the commit author
  name: string;
  email: string;
  username: string;
}

// PayloadCommit represents a commit
type PayloadCommit = {
  // sha1 hash of the commit
  id: string;
  message: string;
  url: string;
  author: PayloadUser;
  committer: PayloadUser;
  verification: PayloadCommitVerification;
  timestamp: Date;
  added: string[];
  removed: string[];
  modified: string[];
}

// PayloadCommitVerification represents the GPG verification of a commit
type PayloadCommitVerification = {
  verified: boolean;
  reason: string;
  signature: string;
  payload: string;
}

// Branch represents a repository branch
type GiteaBranch = {
  name: string;
  commit: PayloadCommit;
  protected: boolean;
  required_approvals: BigInt;
  enable_status_check: boolean;
  status_check_contexts: string[];
  user_can_push: boolean;
  user_can_merge: boolean;
  effective_branch_protection_name: string;
};

type GiteaCommitRef = {
  type: string;
  name: string;
};

type GiteaCommit = {
  id: string;
  short_id: string;
  title: string;
  author_name: string;
  author_email: string;
  authored_date: string;
  committer_name: string;
  committer_email: string;
  committed_date: string;
  created_at: string;
  message: string;
};

type LocalFile = {
  path: string;
  newPath?: string
}

export default class API {
  apiRoot: string;
  token: string | boolean;
  branch: string;
  useOpenAuthoring?: boolean;
  repo: string;
  repoURL: string;
  commitAuthor?: CommitAuthor;
  squashMerges: boolean;
  initialWorkflowStatus: string;
  cmsLabelPrefix: string;

  constructor(config: Config) {
    this.apiRoot = config.apiRoot || 'https://gitea.com/api/v1';
    this.token = config.token || false;
    this.branch = config.branch || 'master';
    this.repo = config.repo || ''; // brankas/site
    this.repoURL = `/repos/${this.repo}`;
    this.squashMerges = config.squashMerges;
    this.initialWorkflowStatus = config.initialWorkflowStatus;
    this.cmsLabelPrefix = config.cmsLabelPrefix;
  }

  withAuthorizationHeaders = (req: ApiRequest) => {
    const withHeaders = unsentRequest.withHeaders(
      this.token ? { Authorization: `Bearer ${this.token}` } : {},
      req,
    );
    return Promise.resolve(withHeaders);
  };

  buildRequest = async (req: ApiRequest) => {
    const withRoot: ApiRequest = unsentRequest.withRoot(this.apiRoot)(req);
    const withAuthorizationHeaders = await this.withAuthorizationHeaders(withRoot);

    if (withAuthorizationHeaders.has('cache')) {
      return withAuthorizationHeaders;
    } else {
      const withNoCache: ApiRequest = unsentRequest.withNoCache(withAuthorizationHeaders);
      return withNoCache;
    }
  };

  request = async (req: ApiRequest): Promise<Response> => {
    try {
      return requestWithBackoff(this, req);
    } catch (err) {
      throw new APIError(err.message, null, API_NAME);
    }
  };

  responseToJSON = responseParser({ format: 'json', apiName: API_NAME });
  responseToBlob = responseParser({ format: 'blob', apiName: API_NAME });
  responseToText = responseParser({ format: 'text', apiName: API_NAME });

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  requestJSON = (req: ApiRequest) => this.request(req).then(this.responseToJSON) as Promise<any>;
  requestText = (req: ApiRequest) => this.request(req).then(this.responseToText) as Promise<string>;

  user = () => this.requestJSON('/user');

  hasWriteAccess = async () => {
    const {
      permissions,
    }: GiteaRepo = await this.requestJSON(this.repoURL);

    const { admin, push } = permissions;
    if (admin) {
      return true;
    }
    if (push) {
      return true;
    }

    return false;
  };

  getFile = async (
    path: string,
    { branch = this.branch } = {},
  ): Promise<any> => {
    const file = await this.requestJSON({
      url: `${this.repoURL}/contents/${encodeURIComponent(path)}`,
      params: { ref: branch },
      cache: 'no-store',
    });
    console.log("getFile", file.constructor === Blob, path, file)

    return file
  };
  readFile = async (
    path: string,
    sha?: string | null,
    { parseText = true, branch = this.branch } = {},
  ): Promise<string | Blob> => {
    console.log("-> readfile")

    // why is this is not executing when the thing is called in GetMediaAsBlob?
    const fetchContent = async () => {
      let file, contentString;
      if (!sha || sha == "") {

        file = await this.GetContent(path, branch)
        contentString = this.fromBase64(file.content)
      } else {
        const result = await this.GetBlob(sha)

        if (parseText) {
          // treat content as a utf-8 string
          const content = Base64.decode(result.content);
          return content;
        } else {
          // treat content as binary and convert to blob
          const content = Base64.atob(result.content);
          const byteArray = new Uint8Array(content.length);
          for (let i = 0; i < content.length; i++) {
            byteArray[i] = content.charCodeAt(i);
          }
          const blob = new Blob([byteArray]);
          return blob;
        }
      }
      return contentString;
    };

    const content = await readFile(sha, fetchContent, localForage, parseText);
    return content;
  };

  async readFileMetadata(path: string, sha: string | null | undefined) {
    const fetchFileMetadata = async () => {
      try {
        const result = await this.GetCommitBySHA(sha);
        const commit = result[0];
        return {
          author: commit.author.full_name || commit.author_email,
          updatedOn: commit.created,
        };
      } catch (e) {
        return { author: '', updatedOn: '' };
      }
    };
    const fileMetadata = await readFileMetadata(sha, fetchFileMetadata, localForage);
    return fileMetadata;
  }

  getCursorFromHeaders = (headers: Headers) => {
    const page = parseInt(headers.get('X-Page') as string, 10);
    const pageCount = parseInt(headers.get('X-Total-Pages') as string, 10);
    const pageSize = parseInt(headers.get('X-Per-Page') as string, 10);
    const count = parseInt(headers.get('X-Total') as string, 10);
    const links = parseLinkHeader(headers.get('Link'));
    const actions = Map(links)
      .keySeq()
      .flatMap(key =>
        (key === 'prev' && page > 1) ||
          (key === 'next' && page < pageCount) ||
          (key === 'first' && page > 1) ||
          (key === 'last' && page < pageCount)
          ? [key]
          : [],
      );
    return Cursor.create({
      actions,
      meta: { page, count, pageSize, pageCount },
      data: { links },
    });
  };

  getCursor = ({ headers }: { headers: Headers }) => this.getCursorFromHeaders(headers);

  // Gets a cursor without retrieving the entries by using a HEAD
  // request
  fetchCursor = (req: ApiRequest) =>
    flow([unsentRequest.withMethod('HEAD'), this.request, then(this.getCursor)])(req);

  fetchCursorAndEntries = (
    req: ApiRequest,
  ): Promise<{
    entries: { id: string; type: string; path: string; name: string }[];
    cursor: Cursor;
  }> =>
    flow([
      unsentRequest.withMethod('GET'),
      this.request,
      p =>
        Promise.all([
          p.then(this.getCursor),
          p.then(this.responseToJSON).catch((e: FetchError) => {
            if (e.status === 404) {
              return [];
            } else {
              throw e;
            }
          }),
        ]),
      then(([cursor, entries]: [Cursor, {}[]]) => {
        const ents = entries.map((ent: any) => ({ ...ent, id: ent.sha }))
        return { cursor, entries: ents }
      }),
    ])(req);

  listFiles = async (path: string, recursive = false) => {
    const { entries, cursor } = await this.fetchCursorAndEntries({
      url: `${this.repoURL}/contents/${encodeURIComponent(path)}`,
      params: { ref: this.branch, recursive },
    });
    return {
      files: entries.filter(({ type }) => type === 'file'),
      cursor,
    };
  };

  traverseCursor = async (cursor: Cursor, action: string) => {
    const link = cursor.data!.getIn(['links', action]);
    const { entries, cursor: newCursor } = await this.fetchCursorAndEntries(link);
    return {
      entries: entries.filter(({ type }) => type === 'file'),
      cursor: newCursor,
    };
  };

  listAllFiles = async (path: string, recursive = false, branch = this.branch) => {
    const entries = [];
    // eslint-disable-next-line prefer-const
    let { entries: initialEntries, cursor } = await this.fetchCursorAndEntries({
      url: `${this.repoURL}/contents/${encodeURIComponent(path)}`,
      // Get the maximum number of entries per page
      params: { ref: branch, per_page: 100, recursive },
    });
    entries.push(...initialEntries);
    while (cursor && cursor.actions!.has('next')) {
      const link = cursor.data!.getIn(['links', 'next']);
      const { cursor: newCursor, entries: newEntries } = await this.fetchCursorAndEntries(link);
      entries.push(...newEntries);
      cursor = newCursor;
    }
    return entries.filter(({ type }) => type === 'file');
  };

  toBase64 = (str: string) => Promise.resolve(Base64.encode(str));
  fromBase64 = (str: string) => Base64.decode(str);

  async getBranch(branchName: string) {
    const branch: GiteaBranch = await this.requestJSON(
      `${this.repoURL}/branches/${encodeURIComponent(branchName)}`,
    );
    return branch;
  }


  async uploadAndCommit(
    items: CommitItem[],
    { commitMessage = '', branch = this.branch },
  ) {
    try {
      for (const item of items) {
        if (item.action == CommitAction.UPDATE) {
          const updateFileOpt: GiteaUpdateFileOption = {
            sha: item.sha,
            content: item.base64Content,
            from_path: item.path,
            signoff: true,
            message: commitMessage,
            branch: branch,
          };
          await this.UpdateFile(item.path, updateFileOpt);
        }
        else if (item.action == CommitAction.CREATE) {
          const createFileOpt: GiteaCreateFileOption = {
            content: item.base64Content,
            signoff: true,
            message: commitMessage,
            branch: branch,
          };
          await this.CreateFile(item.path, createFileOpt);
        }
        else if (item.action == CommitAction.MOVE) {

          const deleteFileOpt: GiteaDeleteFileOption = {
            sha: item.sha,
            signoff: true,
            branch: branch,

          };
          await this.DeleteFile(item.oldPath, deleteFileOpt);

          let createFileOpt: GiteaCreateFileOption = {
            content: item.base64Content,
            signoff: true,
            message: commitMessage,
            branch: branch,
          };
          await this.CreateFile(item.path, createFileOpt);
        } else if (item.action == CommitAction.DELETE) {
          const deleteFileOpt: GiteaDeleteFileOption = {
            sha: item.sha,
            signoff: true,
            branch: branch,
          };
          await this.DeleteFile(item.oldPath, deleteFileOpt);

        } else {
          const updateFileOpt: GiteaUpdateFileOption = {
            sha: item.sha,
            content: item.base64Content,
            from_path: item.path,
            signoff: true,
            message: commitMessage,
            branch: branch,
          };
          await this.UpdateFile(item.path, updateFileOpt);
        }
      }
    } catch (error) {
      throw error;
    }
  }

  async appendCommitMetadata(files: LocalFile[], branch: string) {
    const items: CommitItem[] = await Promise.all(
      files.map(async file => {
        const [base64Content, fileExists] = await Promise.all([
          result(file, 'toBase64', partial(this.toBase64, (file as DataFile).raw)),
          this.isFileExists(file.path, branch),
        ]);

        // Initialize metadata
        let action = CommitAction.CREATE;
        let oldPath = null
        let sha = ""

        const path = trimStart(file.path, '/');

        //  if new file (i.e !oldpath && newpath) CreateFile(newpath)
        //  if move file (i.e oldpath && newpath) DeleteFile(oldpath)
        //  if update file (i.e oldath && (oldpath == newpath)) UpdateFile(newpath)
        //  if delete file (i.e file.delete exists) DeleteFile(oldpath)

        if (fileExists) {
          // add value to oldPath and sha when its not empty
          // fileExists object double down as the `content` if its not boolean
          oldPath = fileExists.path
          sha = fileExists.sha
        }


        // i.e oldPath = 'old', path = 'new'
        if (oldPath && (oldPath != path)) {
          action = CommitAction.MOVE
        } else if (oldPath && (oldPath == path)) {
          action = CommitAction.UPDATE
        } else if (!oldPath) {
          action = CommitAction.CREATE
        } else {
          action = CommitAction.DELETE
        }

        return {
          action,
          base64Content,
          path,
          oldPath,
          sha,
        };
      }),
    );

    return items;
  }

  async persistFiles(dataFiles: DataFile[], mediaFiles: AssetProxy[], options: PersistOptions) {
    const files = [...dataFiles, ...mediaFiles];
    if (options.useWorkflow) {
      const slug = dataFiles[0].slug;
      console.log("persistFiles:useWorkflow", slug, files)
      return this.editorialWorkflowGit(files, slug, options);
    } else {
      const items = await this.appendCommitMetadata(files, this.branch);
      await this.uploadAndCommit(items, {
        commitMessage: options.commitMessage,
        branch: this.branch,
      });
    }
  }

  async deleteFiles(paths: string[], commitMessage: string) {
    let pItems = (paths.map(async (path) => {
      const content = await this.GetContent(path, this.branch)
      return { sha: content.sha, oldPath: path, path: path, action: CommitAction.DELETE }
    }));

    const items = await Promise.all(pItems);
    return this.uploadAndCommit(items, {
      commitMessage,
    });
  };

  async getPullRequests(opt?: GiteaListPullRequestsOptions) {
    const pullRequests: GiteaPullRequest[] = await this.requestJSON({
      url: `${this.repoURL}/pulls`,
      headers: { 'Content-Type': APPLICATION_JSON },
      params: opt,
    });

    return pullRequests.filter(
      mr =>
        mr.head.label.startsWith(CMS_BRANCH_PREFIX)
      // uncomment if we've created labels
      // mr.labels.some(l => isCMSLabel(l, this.cmsLabelPrefix)),
    );
  }

  async listUnpublishedBranches() {
    console.log(
      '%c Checking for Unpublished entries',
      'line-height: 30px;text-align: center;font-weight: bold',
    );
    const getPRsOpt: GiteaListPullRequestsOptions = {
      state: "open"
    }
    const pullRequests = await this.getPullRequests(getPRsOpt);
    const branches = pullRequests.map(pull => pull.head.label);

    return branches;
  }

  async getFileId(path: string, branch: string) {
    let sha: string
    const content = await this.requestJSON({
      url: `${this.repoURL}/contents/${encodeURIComponent(path)}`,
      params: { ref: branch },
    })
    sha = content.sha
    return sha;
  }

  // checks if file exists in repo already
  // so we know whether to CreateFile or UpdateFile
  async isFileExists(path: string, branch: string) {
    const fileExists = await this.GetContent(path, branch)
      .catch(error => {
        if (error instanceof APIError && error.status === 404) {
          return false;
        }
        throw error;
      });

    return fileExists;
  }

  // gets a pull request from a specific head.branch
  async getBranchPullRequest(branch: string) {
    const getPRsOpt: GiteaListPullRequestsOptions = {
      state: "open"
    }
    const pulls = await this.getPullRequests(getPRsOpt);
    if (pulls.length <= 0) {
      throw new EditorialWorkflowError('content is not under editorial workflow', true);
    }

    const filtered = pulls.filter(pull => pull.head.label == branch)
    if (filtered.length == 0) {
      return null
    }

    return filtered[0];

  }

  async getPullDifferences(index: any) {
    const rawDiff = await this.requestText({
      url: `${this.repoURL}/pulls/${index}.diff`,
      params: {
        binary: false,
      },
    });

    const diffs = gd.parse(rawDiff).map(d => {
      const oldPath = d.oldPath?.replace(/b\//, '') || '';
      const newPath = d.newPath?.replace(/b\//, '') || '';
      const path = newPath || (oldPath as string);
      return {
        oldPath,
        newPath,
        status: d.type as string,
        newFile: (d.type as string) === 'added',
        path,
        binary: d.isBinary || /.svg$/.test(path) || d.hunks.length == 0,
      };
    });

    return diffs.filter((d) => d.binary == false);
  }

  async retrieveUnpublishedEntryData(contentKey: string) {
    const { collection, slug } = parseContentKey(contentKey);
    const branch = branchFromContentKey(contentKey);
    const pullRequest = await this.getBranchPullRequest(branch);

    // If no PRs are retrieved, we return null
    // This will allow the backend to choose from `publishedEntries` instead
    if (!pullRequest) {
      return null
    }

    const diffs = await this.getPullDifferences(pullRequest.number);
    const diffsWithIds = await Promise.all(
      diffs.map(async d => {
        const { path, newFile } = d;
        const id = await this.getFileId(path, branch);
        return { id, path, newFile };
      }),
    );

    const label = pullRequest.labels.find(l => isCMSLabel(l.name, this.cmsLabelPrefix));
    const status = labelToStatus(label.name, this.cmsLabelPrefix);
    const updatedAt = pullRequest.updated_at;
    const author = pullRequest.user.full_name
    return {
      collection,
      slug,
      status,
      diffs: diffsWithIds,
      updatedAt,
      author,
    };
  }

  // GetCommitBySHA get the metadata and contents of existing file in repository
  async GetCommitBySHA(commitID: string) {
    const response = await this.requestJSON({
      method: 'GET',
      url: `${this.repoURL}/git/commits/${commitID}`,
    });
    return response;
  }

  // GetContent get the metadata and contents of existing file in repository
  async GetContent(filepath: string, ref?: string) {
    const response = await this.requestJSON({
      method: 'GET',
      url: `${this.repoURL}/contents/${encodeURIComponent(filepath)}`,
      params: { ref: ref }
    });
    return response;
  }

  // GetBlob given the sha
  async GetBlob(sha: string) {
    const response = await this.requestJSON({
      method: 'GET',
      url: `${this.repoURL}/git/blobs/${sha}`,
    });
    return response;
  }

  // CreateFile uploads new file to repository
  async CreateFile(filepath: string, opt: GiteaCreateFileOption) {
    const response = await this.requestJSON({
      method: 'POST',
      url: `${this.repoURL}/contents/${encodeURIComponent(filepath)}`,
      headers: { 'Content-Type': APPLICATION_JSON },
      body: JSON.stringify(opt),
    });
    return response;
  }

  // UpdateFile updates file in repository
  async UpdateFile(filepath: string, opt: GiteaUpdateFileOption) {
    const response = await this.requestJSON({
      method: 'PUT',
      url: `${this.repoURL}/contents/${encodeURIComponent(filepath)}`,
      headers: { 'Content-Type': APPLICATION_JSON },
      body: JSON.stringify(opt),
    });
    return response;
  }


  // DeleteFile updates file in repository
  async DeleteFile(filepath: string, opt: GiteaDeleteFileOption) {
    const response = await this.requestJSON({
      method: 'DELETE',
      url: `${this.repoURL}/contents/${encodeURIComponent(filepath)}`,
      headers: { 'Content-Type': APPLICATION_JSON },
      body: JSON.stringify(opt),
    });
    return response;
  }

  // Creates branch 
  async createBranch(opt: GiteaCreateBranchOption) {
    await this.requestJSON({
      method: 'POST',
      url: `${this.repoURL}/branches`,
      headers: { 'Content-Type': APPLICATION_JSON },
      body: JSON.stringify(opt),
    });
  }

  // Delete branch 
  async deleteBranch(branch: string) {
    await this.request({
      method: 'DELETE',
      url: `${this.repoURL}/branches/${branch}`,
    });
  }


  // Creates pull request https://try.gitea.io/api/swagger#/repository/repoCreatePullRequest
  async createPullRequest(opt: GiteaCreatePullRequestOption) {
    await this.requestJSON({
      method: 'POST',
      headers: { 'Content-Type': 'application/json; charset=utf-8' },
      url: `${this.repoURL}/pulls`,
      headers: { 'Content-Type': APPLICATION_JSON },
      body: JSON.stringify(opt),
    });
  }

  async editorialWorkflowGit(
    files: (DataFile | AssetProxy)[],
    slug: string,
    options: PersistOptions,
  ) {
    const contentKey = generateContentKey(options.collectionName as string, slug);
    const branch = branchFromContentKey(contentKey);
    const unpublished = options.unpublished || false;
    if (!unpublished) {
      let createBranchOpt: GiteaCreateBranchOption = {
        new_branch_name: branch,
        old_branch_name: this.branch,
      };
      await this.createBranch(createBranchOpt)

      const items = await this.appendCommitMetadata(files, this.branch);
      await this.uploadAndCommit(items, {
        commitMessage: options.commitMessage,
        branch: branch,
      });

      const repoLabels: GiteaLabel[] = await this.requestJSON({
        method: 'GET',
        url: `${this.repoURL}/labels`,
      });

      const status = options.status || this.initialWorkflowStatus
      const lname = statusToLabel(status, this.cmsLabelPrefix)
      const cmsLabel = await repoLabels.filter(l => l.name == lname)

      const createPullRequestOpt: GiteaCreatePullRequestOption = {
        head: branch,
        base: this.branch, // master
        title: options.commitMessage,
        body: DEFAULT_PR_BODY,
        labels: [cmsLabel[0].id],

      };
      await this.createPullRequest(createPullRequestOpt);
    } else {
      const pullRequest: GiteaPullRequest = await this.getBranchPullRequest(branch)

      // mark files for deletion
      const diffs = await this.getPullDifferences(pullRequest.number);
      const toDelete: DeleteEntry[] = [];
      for (const diff of diffs.filter(d => d.binary && d.status !== 'deleted' && d.path)) {
        if (!files.some(file => file.path === diff.path)) {
          toDelete.push({ path: diff.path, action: CommitAction.DELETE });
        }
      }

      const items = await this.appendCommitMetadata(files, branch);
      await this.uploadAndCommit([...items, ...toDelete], {
        commitMessage: options.commitMessage,
        branch,
      });

    }
  }

  async updatePullRequest(index: any, opt: GiteaEditPullRequestOption) {
    await this.requestJSON({
      method: 'PATCH',
      url: `${this.repoURL}/pulls/${index}`,
      headers: { 'Content-Type': APPLICATION_JSON },
      body: JSON.stringify(opt),
    });
  }

  async createLabel(opt: GiteaCreateLabelOption) {
    return await this.requestJSON({
      method: 'POST',
      url: `${this.repoURL}/labels`,
      headers: { 'Content-Type': APPLICATION_JSON },
      body: JSON.stringify(opt),
    });
  }

  async updateUnpublishedEntryStatus(collection: string, slug: string, newStatus: string) {
    const contentKey = generateContentKey(collection, slug);
    const branch = branchFromContentKey(contentKey);
    const pullRequest = await this.getBranchPullRequest(branch);


    // all the old labels that are not CMS label + label from newStatus
    const labels = [
      ...pullRequest.labels
        .filter(label => !isCMSLabel(label.name, this.cmsLabelPrefix))
        .map(l => l.name),
      statusToLabel(newStatus, this.cmsLabelPrefix),
    ];


    // get all existing labels
    const repoLabels: GiteaLabel[] = await this.requestJSON({
      method: 'GET',
      url: `${this.repoURL}/labels`,
    });

    // if new status doesnt exist, create label for it
    const newLabel = statusToLabel(newStatus, this.cmsLabelPrefix)
    const isAlreadyExists = repoLabels.find((l) => {
      return l.name == newLabel
    })

    const intLabels: any = []
    if (!isAlreadyExists) {
      const opt: GiteaCreateLabelOption = {
        color: "#00aabb",
        name: newLabel,
        description: `Tagging cms entries of status ${newStatus}`
      }
      // create label & push its id to intLabels
      const respLabel: GiteaLabel = await this.createLabel(opt)
      intLabels.push(respLabel.id)
    }



    // push old corresponding id to `intLabels`
    labels.forEach(label => {
      const matchingLabel = repoLabels.find((l) => {
        return l.name == label
      })
      intLabels.push(matchingLabel.id);
    });

    const editPullRequestOpt: GiteaEditPullRequestOption = {
      labels: intLabels,
    }
    await this.updatePullRequest(pullRequest.number, editPullRequestOpt);
  }

  async mergePullRequest(index: any, opt: GiteaMergePullRequestOption) {
    await this.request({
      method: 'POST',
      url: `${this.repoURL}/pulls/${index}/merge`,
      headers: { 'Content-Type': APPLICATION_JSON },
      body: JSON.stringify(opt),
    });
  }

  async publishUnpublishedEntry(collectionName: string, slug: string) {
    const contentKey = generateContentKey(collectionName, slug);
    const branch = branchFromContentKey(contentKey);
    const pullRequest = await this.getBranchPullRequest(branch);
    const mergePullRequestOpt: GiteaMergePullRequestOption = {
      Do: "rebase",
      MergeTitleField: "trial cms",
      MergeMessageField: "merge via cms",
    }
    await this.mergePullRequest(pullRequest.number, mergePullRequestOpt);
    await this.deleteBranch(branch)
  }

  async closePullRequest(pullRequest: GiteaPullRequest) {
    // // StateOpen pr/issue is opend
    // StateOpen StateType = "open"
    // // StateClosed pr/issue is closed
    // StateClosed StateType = "closed"
    // // StateAll is all
    // StateAll StateType = "all"
    const editPullRequestOpt: GiteaEditPullRequestOption = {
      state: "closed",
    }
    return await this.updatePullRequest(pullRequest.number, editPullRequestOpt)
  }

  async getDefaultBranch() {
    const branch: GiteaBranch = await this.getBranch(this.branch);
    return branch;
  }

  async isShaExistsInBranch(branch: string, sha: string) {
    const refs: GiteaCommitRef[] = await this.requestJSON({
      url: `${this.repoURL}/commits/${sha}/refs`,
      params: {
        type: 'branch',
      },
    });
    return refs.some(r => r.name === branch);
  }

  async deleteUnpublishedEntry(collectionName: string, slug: string) {
    const contentKey = generateContentKey(collectionName, slug);
    const branch = branchFromContentKey(contentKey);
    const pullRequest = await this.getBranchPullRequest(branch);
    const re = await this.closePullRequest(pullRequest);
    const re2 = await this.deleteBranch(branch);

  }

  async getUnpublishedEntrySha(collection: string, slug: string) {
    const contentKey = generateContentKey(collection, slug);
    const branch = branchFromContentKey(contentKey);
    const pullRequest = await this.getBranchPullRequest(branch);
    return pullRequest.head.sha;
  }


  /**
 * Retrieve statuses for a given SHA. Unrelated to the editorial workflow
 * concept of entry "status". Useful for things like deploy preview links.
 */
  async getStatuses(collectionName: string, slug: string) {
    const contentKey = generateContentKey(collectionName, slug);
    const branch = branchFromContentKey(contentKey);
    const pullRequest = await this.getBranchPullRequest(branch);
    const statuses: GiteaCommitStatus[] = await this.getPullRequestStatues(pullRequest, branch);
    return statuses.map(({ name, status, target_url }) => ({
      context: name,
      state: status === GiteaCommitStatuses.Success ? PreviewState.Success : PreviewState.Other,
      target_url,
    }));
  }

  async getPullRequestStatues(pullRequest: GiteaPullRequest, branch: string) {
    const statuses: GiteaCommitStatus[] = await this.requestJSON({
      url: `${this.repoURL}/commits/${encodeURIComponent(branch)}/statuses`,
      params: {
        ref: branch,
      },
    });
    return statuses;
  }
}
