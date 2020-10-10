#!/usr/bin/env python
# -*- coding: utf-8 -*-

from __future__ import absolute_import
import schedule
import time
import pexpect
import logging
import git
import shutil
import math
import datetime
import uuid
import hashlib
import os
import re
import json
import stat
from git import Repo
from git import NULL_TREE
from truffleHogRegexes.regexChecks import regexes
import defectdojo
from datetime import datetime, timedelta
from random import randint
import configparser
import sys


"""
Searching part is borrowed from Trufflehog (https://github.com/dxa4481/truffleHog) and customized accordingly
"""



config = {}
status_conf = {}

# dir path
codeguard_path = "codeguard/"
projects_path = codeguard_path + "projects/"
alerts_path = codeguard_path + "results/"
logs_path = codeguard_path + "logs/"
conf_path = codeguard_path + "conf/"
codeguard_config_file = conf_path + "codeguard.conf"
codeguard_repository_file = conf_path + "repository.json"

# logging
logging.basicConfig(format='%(asctime)s - [%(levelname)s] %(message)s', level=logging.INFO, filename=logs_path+"codeguard.log")
logging.info('Started GodeGuard')


# check for necessary folders
if not os.path.exists(projects_path):
    os.makedirs(projects_path)
if not os.path.exists(alerts_path):
    os.makedirs(alerts_path)
if not os.path.exists(logs_path):
    os.makedirs(logs_path)
if not os.path.exists(conf_path):
    os.makedirs(conf_path)

# check for required files
if not os.path.exists(codeguard_config_file):
    logging.error("codeguard.conf not found.")
    sys.exit(1)
if not os.path.exists(codeguard_repository_file):
    logging.error("repository.json not found.")
    sys.exit(1)


# config parser
with open(codeguard_config_file) as f:
    config_content = '[root]\n' + f.read()

config_parser = configparser.ConfigParser()
config_parser.read_string(config_content)

"""
Config params
"""
# setup DefectDojo connection information
defectdojo_url = config_parser["root"]["defectdojo_url"]
defectdojo_api_key = config_parser["root"]["defectdojo_api_key"]
defectdojo_user = config_parser["root"]["defectdojo_user"]

clean_projects_directory = False
if config_parser["root"]["clean_projects_directory"] == "true":
    clean_projects_directory = True
elif config_parser["root"]["clean_projects_directory"] == "false":
    clean_projects_directory = False

# defect dojo API
dd = defectdojo.DefectDojoAPI(defectdojo_url, defectdojo_api_key, defectdojo_user, debug=False, verify_ssl=False)
prod_type = 1



# Shannon entropy chars
BASE64_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="
HEX_CHARS = "1234567890abcdefABCDEF"


def del_rw(action, name, exc):
    """
    Forcefully removing temp project

    :param action:
    :param name:
    :param exc:
    :return:
    """

    os.chmod(name, stat.S_IWRITE)
    os.remove(name)


class bcolors:
    """
    Class for terminal colors
    """

    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'


def upload_to_defectdojo(repository_name, project_name, branch_name, results_file):
    """
    Function to upload results to defect dojo
    :param repository_name:
    :param project_name:
    :param branch_name:
    :param results_file:
    :return:
    """
    product_id = ""
    product_name = repository_name
    product = dd.list_products(name=product_name)

    if product.count() is not 0:
        product_id = product.data["objects"][0]["id"]
    else:
        prod_type = 1
        product = dd.create_product(product_name, product_name, prod_type)

        product_id = product.id()

    product = dd.get_product(product_id)

    engagement = dd.list_engagements(product=product_id,
                                     name_contains="" + repository_name + "-" + project_name + "" )
    engagement_id = None
    start_date = datetime.now()
    end_date = start_date+timedelta(days=randint(2,8))

    if engagement.count() > 0:
        for engagement in engagement.data["objects"]:
            engagement_id = engagement['id']
    else:
        # Create an engagement
        engagement = dd.create_engagement(name=" " + repository_name + "-" + project_name + " ",
                                          product_id=product_id,
                                          lead_id=1,
                                          status="In Progress",
                                          target_start=start_date.strftime("%Y-%m-%d"),
                                          target_end=end_date.strftime("%Y-%m-%d"))
        engagement_id = engagement.id()

    scanner = "Trufflehog Scan"
    file = os.path.join(alerts_path, results_file)
    date = datetime.now()
    dojoDate = date.strftime("%Y-%m-%d")

    test_id = dd.upload_scan(engagement_id, scanner, file, "true", dojoDate, tags=branch_name)

    if test_id.success == False:
        print("Upload failed: " + project_name + " " + branch_name +". Detailed error message: " + test_id.data)
        time.sleep(10)
        test_id = dd.upload_scan(engagement_id, scanner, file, "true", dojoDate, tags=branch_name)

    if test_id.success == True:
        # remove results file after successful upload to DefectDojo
        os.remove(file)


def shannon_entropy(data, iterator):
    """
    Shannon entropy calculation
    Borrowed from http://blog.dkbza.org/2007/05/scanning-data-for-entropy-anomalies.html
    """
    if not data:
        return 0
    entropy = 0
    for x in iterator:
        p_x = float(data.count(x))/len(data)
        if p_x > 0:
            entropy += - p_x*math.log(p_x, 2)
    return entropy


def get_strings_of_set(word, char_set, threshold=20):
    """
    Getting hex and base64 strings from the set
    :param word:
    :param char_set:
    :param threshold:
    :return:
    """
    count = 0
    letters = ""
    strings = []
    for char in word:
        if char in char_set:
            letters += char
            count += 1
        else:
            if count > threshold:
                strings.append(letters)
            letters = ""
            count = 0
    if count > threshold:
        strings.append(letters)
    return strings


def find_strings(git_url,
                 saved_project_name,
                 results_file,
                 since_commit=None,
                 max_depth=1000000,
                 printJson=True,
                 do_regex=False,
                 do_entropy=True,
                 surpress_output=True,
                 custom_regexes={},
                 branch='master',
                 repo_path=None,
                 path_inclusions=None,
                 path_exclusions=None):
    """
    Commit iteration to search strings

    :param git_url:
    :param saved_project_name:
    :param results_file:
    :param since_commit:
    :param max_depth:
    :param printJson:
    :param do_regex:
    :param do_entropy:
    :param surpress_output:
    :param custom_regexes:
    :param branch:
    :param repo_path:
    :param path_inclusions:
    :param path_exclusions:
    :return:
    """
    #project_uuid = str(uuid.uuid4())

    #status_conf[saved_project_name]["branches"][branch].update({ "results_file" : "test"})

    project_path = repo_path
    output = {"foundIssues": []}
    repo = Repo(project_path)
    already_searched = set()
    branches = repo.remotes.origin.fetch()

    """
    if repo_path:
        project_path = repo_path
    else:
        project_path = clone_git_repo(git_url)
    """

    # update_repository(git_url, repo_path)
    repo = Repo(repo_path)
    project_path = repo_path

    already_searched = set()
    output_dir = alerts_path

    #if branch:
    #    branches = repo.remotes.origin.fetch(branch)
    #else:
    #    branches = repo.remotes.origin.fetch()

    remote_branch_name = "{0}".format(branch)

    since_commit_reached = False
    branch_name = remote_branch_name
    prev_commit = None
    for curr_commit in repo.iter_commits(branch_name, max_count=max_depth):
        commitHash = curr_commit.hexsha

        # This code needs to be improved.
        # Iteration does not stop at since commit.
        if commitHash == since_commit:
            since_commit_reached = True
        if since_commit and since_commit_reached:
            prev_commit = curr_commit
            continue
            #return output
        # if not prev_commit, then curr_commit is the newest commit. And we have nothing to diff with.
        # But we will diff the first commit with NULL_TREE here to check the oldest code.
        # In this way, no commit will be missed.
        diff_hash = hashlib.md5((str(prev_commit) + str(curr_commit)).encode('utf-8')).digest()
        if not prev_commit:
            prev_commit = curr_commit
            continue
        elif diff_hash in already_searched:
            prev_commit = curr_commit
            continue
        else:
            diff = prev_commit.diff(curr_commit, create_patch=True)

        # avoid searching the same diffs
        already_searched.add(diff_hash)
        foundIssues = diff_worker(diff,
                                  curr_commit,
                                  prev_commit,
                                  branch_name,
                                  commitHash,
                                  custom_regexes,
                                  do_entropy,
                                  do_regex,
                                  printJson,
                                  surpress_output,
                                  path_inclusions,
                                  path_exclusions,
                                  results_file=results_file)
        output = handle_results(output, output_dir, foundIssues)
        prev_commit = curr_commit

    # Handling the first commit
    diff = curr_commit.diff(NULL_TREE, create_patch=True)
    foundIssues = diff_worker(diff,
                              curr_commit,
                              prev_commit,
                              branch_name,
                              commitHash,
                              custom_regexes,
                              do_entropy,
                              do_regex,
                              printJson,
                              surpress_output,
                              path_inclusions,
                              path_exclusions,
                              results_file=results_file)
    output = handle_results(output, output_dir, foundIssues)

    output["project_path"] = project_path
    output["clone_uri"] = git_url
    output["issues_path"] = output_dir

    if not repo_path:
        shutil.rmtree(project_path, onerror=del_rw)
    return output


def clone_git_repo(git_url, project_path):
    """
    Cloning git repo

    :param git_url:
    :param project_path:
    :return:
    """
    Repo.clone_from(git_url, project_path)
    return project_path


def print_results(printJson, issue, results_file):
    """
    Printing/Writing results

    :param printJson:
    :param issue:
    :param results_file:
    :return:
    """
    commit_time = issue['date']
    branch_name = issue['branch']
    prev_commit = issue['commit']
    # printableDiff = issue['printDiff']
    commitHash = issue['commitHash']
    reason = issue['reason']
    path = issue['path']


    if printJson:
        # print(json.dumps(issue, sort_keys=True))
        result_path = os.path.join(alerts_path, results_file)
        with open(result_path, "a+") as result_file:
            result_file.write(json.dumps(issue, sort_keys=True) + "\n")
    """
    else:
        print("~~~~~~~~~~~~~~~~~~~~~")
        reason = "{}Reason: {}{}".format(bcolors.OKGREEN, reason, bcolors.ENDC)
        print(reason)
        dateStr = "{}Date: {}{}".format(bcolors.OKGREEN, commit_time, bcolors.ENDC)
        print(dateStr)
        hashStr = "{}Hash: {}{}".format(bcolors.OKGREEN, commitHash, bcolors.ENDC)
        print(hashStr)
        filePath = "{}Filepath: {}{}".format(bcolors.OKGREEN, path, bcolors.ENDC)
        print(filePath)

        if sys.version_info >= (3, 0):
            branchStr = "{}Branch: {}{}".format(bcolors.OKGREEN, branch_name, bcolors.ENDC)
            print(branchStr)
            commitStr = "{}Commit: {}{}".format(bcolors.OKGREEN, prev_commit, bcolors.ENDC)
            print(commitStr)
            print(printableDiff)
        else:
            branchStr = "{}Branch: {}{}".format(bcolors.OKGREEN, branch_name.encode('utf-8'), bcolors.ENDC)
            print(branchStr)
            commitStr = "{}Commit: {}{}".format(bcolors.OKGREEN, prev_commit.encode('utf-8'), bcolors.ENDC)
            print(commitStr)
            print(printableDiff.encode('utf-8'))
        print("~~~~~~~~~~~~~~~~~~~~~")
    """


def find_entropy(printableDiff, commit_time, branch_name, prev_commit, blob, commitHash):
    """
    Finding high entropy strings

    :param printableDiff:
    :param commit_time:
    :param branch_name:
    :param prev_commit:
    :param blob:
    :param commitHash:
    :return:
    """
    stringsFound = []
    lines = printableDiff.split("\n")
    for line in lines:
        for word in line.split():
            base64_strings = get_strings_of_set(word, BASE64_CHARS)
            hex_strings = get_strings_of_set(word, HEX_CHARS)
            for string in base64_strings:
                b64Entropy = shannon_entropy(string, BASE64_CHARS)
                if b64Entropy > 4.5:
                    stringsFound.append(string)
                    printableDiff = printableDiff.replace(string, bcolors.WARNING + string + bcolors.ENDC)
            for string in hex_strings:
                hexEntropy = shannon_entropy(string, HEX_CHARS)
                if hexEntropy > 3:
                    stringsFound.append(string)
                    printableDiff = printableDiff.replace(string, bcolors.WARNING + string + bcolors.ENDC)
    entropicDiff = None
    if len(stringsFound) > 0:
        entropicDiff = {}
        entropicDiff['date'] = commit_time
        entropicDiff['path'] = blob.b_path if blob.b_path else blob.a_path
        entropicDiff['branch'] = branch_name
        entropicDiff['commit'] = prev_commit.message
        #entropicDiff['diff'] = blob.diff.decode('utf-8', errors='replace')
        entropicDiff['stringsFound'] = stringsFound
        #entropicDiff['printDiff'] = printableDiff
        entropicDiff['commitHash'] = prev_commit.hexsha
        entropicDiff['reason'] = "High Entropy"
    return entropicDiff


def regex_check(printableDiff, commit_time, branch_name, prev_commit, blob, commitHash, custom_regexes={}):
    """
    Finding regex matches

    :param printableDiff:
    :param commit_time:
    :param branch_name:
    :param prev_commit:
    :param blob:
    :param commitHash:
    :param custom_regexes:
    :return:
    """
    if custom_regexes:
        secret_regexes = custom_regexes
    else:
        secret_regexes = regexes
    regex_matches = []
    for key in secret_regexes:
        found_strings = secret_regexes[key].findall(printableDiff)
        for found_string in found_strings:
            found_diff = printableDiff.replace(printableDiff, bcolors.WARNING + found_string + bcolors.ENDC)
        if found_strings:
            foundRegex = {}
            foundRegex['date'] = commit_time
            foundRegex['path'] = blob.b_path if blob.b_path else blob.a_path
            foundRegex['branch'] = branch_name
            foundRegex['commit'] = prev_commit.message
            #foundRegex['diff'] = blob.diff.decode('utf-8', errors='replace')
            foundRegex['stringsFound'] = found_strings
            #foundRegex['printDiff'] = found_diff
            foundRegex['reason'] = key
            foundRegex['commitHash'] = prev_commit.hexsha
            regex_matches.append(foundRegex)
    return regex_matches


def diff_worker(diff,
                curr_commit,
                prev_commit,
                branch_name,
                commitHash,
                custom_regexes,
                do_entropy,
                do_regex,
                printJson,
                surpress_output,
                path_inclusions,
                path_exclusions,
                results_file):
    """
    Diff worker to execute regex and shannon entropy checks

    :param diff:
    :param curr_commit:
    :param prev_commit:
    :param branch_name:
    :param commitHash:
    :param custom_regexes:
    :param do_entropy:
    :param do_regex:
    :param printJson:
    :param surpress_output:
    :param path_inclusions:
    :param path_exclusions:
    :param results_file:
    :return:
    """
    issues = []
    for blob in diff:
        printableDiff = blob.diff.decode('utf-8', errors='replace')
        if printableDiff.startswith("Binary files"):
            continue
        if not path_included(blob, path_inclusions, path_exclusions):
            continue
        commit_time =  datetime.fromtimestamp(prev_commit.committed_date).strftime('%Y-%m-%d %H:%M:%S')
        foundIssues = []
        if do_entropy:
            entropicDiff = find_entropy(printableDiff,
                                        commit_time,
                                        branch_name,
                                        prev_commit,
                                        blob,
                                        commitHash)
            if entropicDiff:
                foundIssues.append(entropicDiff)
        if do_regex:
            found_regexes = regex_check(printableDiff,
                                        commit_time,
                                        branch_name,
                                        prev_commit,
                                        blob,
                                        commitHash,
                                        custom_regexes)
            foundIssues += found_regexes
        if not surpress_output:
            for foundIssue in foundIssues:
                print_results(printJson, foundIssue, results_file=results_file)
        issues += foundIssues
    return issues


def handle_results(output, output_dir, foundIssues):
    """
    Handling searched results

    :param output:
    :param output_dir:
    :param foundIssues:
    :return:
    """
    #for foundIssue in foundIssues:
        #result_path = os.path.join(output_dir, str(uuid.uuid4()))
        #with open(result_path, "w+") as result_file:
        #    result_file.write(json.dumps(foundIssue))
        #output["foundIssues"].append(result_path)
    return output


def path_included(blob, include_patterns=None, exclude_patterns=None):
    """Check if the diff blob object should included in analysis.
    If defined and non-empty, `include_patterns` has precedence over `exclude_patterns`, such that a blob that is not
    matched by any of the defined `include_patterns` will be excluded, even when it is not matched by any of the defined
    `exclude_patterns`. If either `include_patterns` or `exclude_patterns` are undefined or empty, they will have no
    effect, respectively. All blobs are included by this function when called with default arguments.
    :param blob: a Git diff blob object
    :param include_patterns: iterable of compiled regular expression objects; when non-empty, at least one pattern must
     match the blob object for it to be included; if empty or None, all blobs are included, unless excluded via
     `exclude_patterns`
    :param exclude_patterns: iterable of compiled regular expression objects; when non-empty, _none_ of the patterns may
     match the blob object for it to be included; if empty or None, no blobs are excluded if not otherwise
     excluded via `include_patterns`
    :return: False if the blob is _not_ matched by `include_patterns` (when provided) or if it is matched by
    `exclude_patterns` (when provided), otherwise returns True
    """
    path = blob.b_path if blob.b_path else blob.a_path
    if include_patterns and not any(p.match(path) for p in include_patterns):
        return False
    if exclude_patterns and any(p.match(path) for p in exclude_patterns):
        return False
    return True


def clean_up(output):
    """
    Cleaning issues output

    :param output:
    :return:
    """
    print("Whhaat")
    issues_path = output.get("issues_path", None)
    if issues_path and os.path.isdir(issues_path):
        shutil.rmtree(output["issues_path"])


def update_repository(git_url, project_path):
    """
    Updating project to latest version

    :param git_url:
    :param project_path:
    :return:
    """
    logging.info("Starting to update project git repository: " + git_url)
    if os.path.isdir(project_path):
        #download_repository = 'git -C {0} pull'.format(project_path)
        g = git.cmd.Git(project_path)
        g.pull()
    else:
        #download_repository = 'git -c http.sslVerify=false clone {0} {1}'.format(git_url, project_path)
        Repo.clone_from(git_url, project_path)
        #print(download_repository)
    #os.system(download_repository)


def update_status(project_path, saved_project_name):
    """
    Getting list of project branches and updating to status conf

    :param project_path:
    :param saved_project_name:
    :return:
    """
    logging.info("Starting to update project status: " + saved_project_name)
    commits_dict = {}
    repo = Repo(project_path)
    branches = repo.remotes.origin.fetch()
    for branch in branches:
        commits_dict[str(branch)] = {}

    status_conf[saved_project_name]["branches"] = commits_dict


def update_branch(project_path, saved_project_name, branch_name, latest_commit_hash):
    """
    Updating latest commit hash to status conf for incremental scans

    :param project_path:
    :param saved_project_name:
    :param branch_name:
    :param latest_commit_hash:
    :return:
    """

    logging.info("Starting to update latest commit hash for: " + saved_project_name + ":" + branch_name)
    commits_dict = {}

    commits_dict[branch_name] = {"latest_commit_hash": latest_commit_hash}

    status_conf[saved_project_name]["branches"][branch_name].update(commits_dict[branch_name])


def get_scan_branches(saved_project_name):
    """
    Getting branches to scan.
    If there are more then 3 branches, master branch will be choosed to scan

    :param saved_project_name:
    :return:
    """
    logging.info("Getting scan branches for: " + saved_project_name)
    branches_count = len(status_conf[saved_project_name]["branches"])
    branches = {}
    if branches_count > 4:
        branches["origin/master"] = status_conf[saved_project_name]["branches"]["origin/master"]
    else:
        branches = status_conf[saved_project_name]["branches"]
    return branches


def scan_branch(project_path,
                branch_name,
                is_new_project,
                branch_dict,
                saved_project_name,
                results_file,
                git_repo_object,
                repository_name,
                project_name,
                git_url):
    """
    Search logic for branches.

    :param project_path:
    :param branch_name:
    :param is_new_project:
    :param branch_dict:
    :param saved_project_name:
    :param results_file:
    :param git_repo_object:
    :param repository_name:
    :param project_name:
    :return:
    """
    logging.info("Starting to scan branch: " + branch_name)
    latest_commit_hash = ""

    if 'latest_commit_hash' in branch_dict:
        is_new_project = False
    else:
        is_new_project = True

    if is_new_project:
        #for commit in git_repo_object.iter_commits(branch_name,max_count=1):
        #    latest_commit_hash = commit.hexsha
        latest_commit_hash = None
    else:
        latest_commit_hash = branch_dict["latest_commit_hash"]

    if is_new_project:
        scan = "python3 truffleHog.py --regex --repo_path {0} --json --branch {1} >> {2}".format(project_path,
                                                                                                 branch_name,
                                                                                                 results_file)
    else:
        scan = "python3 truffleHog.py --regex --repo_path {0} --json --since_commit {1} --branch {2} >> {3}".format(project_path,
                                                                                                                    latest_commit_hash,
                                                                                                                    branch_name,
                                                                                                                    results_file)

    # output = find_strings(args.git_url, args.since_commit, args.max_depth, args.output_json, args.do_regex, do_entropy, surpress_output=False, branch=args.branch, repo_path=args.repo_path, path_inclusions=path_inclusions, path_exclusions=path_exclusions)

    output = find_strings(git_url=git_url,
                          saved_project_name=saved_project_name,
                          results_file=results_file,
                          since_commit=latest_commit_hash,
                          max_depth=1000000,
                          printJson=True,
                          do_regex=True,
                          do_entropy=True,
                          surpress_output=False,
                          branch=branch_name,
                          repo_path=project_path,
                          path_inclusions=[],
                          path_exclusions=[],)
    # os.system(scan)
    upload_to_defectdojo(repository_name=repository_name,
                         project_name=project_name,
                         branch_name=branch_name,
                         results_file=results_file)

    for commit in git_repo_object.iter_commits(branch_name,max_count=2):
        latest_commit_hash = commit.hexsha
    update_branch(project_path=project_path,
                  saved_project_name=saved_project_name,
                  branch_name=branch_name,
                  latest_commit_hash=latest_commit_hash)


def scan_project(saved_project_name,
                 result_file_name,
                 git_url,
                 project_path,
                 is_new_project,
                 git_repo_object,
                 repository_name,
                 project_name):
    """
    Search logic for projects in one repository.

    :param saved_project_name:
    :param result_file_name:
    :param git_url:
    :param project_path:
    :param is_new_project:
    :param git_repo_object:
    :param repository_name:
    :param project_name:
    :return:
    """

    logging.info("Starting to scan project: " + saved_project_name)
    branches = get_scan_branches(saved_project_name=saved_project_name)

    for branch_name, branch_dict in branches.items():
        result_file_name = ""
        if "results_file" not in status_conf[saved_project_name]["branches"][branch_name].keys():
            project_uuid = str(uuid.uuid4())
            result_file_name = repository_name + "-" + project_name + "-" + project_uuid + ".json"
            status_conf[saved_project_name]["branches"][branch_name].update({ "results_file" : result_file_name})
        else:
            result_file_name = status_conf[saved_project_name]["branches"][branch_name]["results_file"]

        scan_branch(project_path=project_path,
                    branch_name=branch_name,
                    is_new_project=is_new_project,
                    branch_dict=branch_dict,
                    saved_project_name=saved_project_name,
                    results_file=result_file_name,
                    git_repo_object=git_repo_object,
                    repository_name=repository_name,
                    project_name=project_name,
                    git_url=git_url)


def init_project(repository_name, project_name, config):
    """
    Initialize code project for scanning

    :param repository_name:
    :param project_name:
    :param config:
    :return:
    """
    logging.info("Initializing project: " + repository_name + ":" + project_name)
    is_new_project = False
    git_repository = config[repository_name]
    git_project = git_repository["projects"][project_name]
    git_url = git_project["url"]

    git_url_split = re.split("/|@", git_url)
    #protocol = git_repository["protocol"]

    project_name = re.findall('(.*?).git', git_url_split[len(git_url_split)-1])[0]

    #repository_name = git_url_split[len(git_url_split)-2]

    saved_project_name = "{0}_{1}".format(repository_name,project_name)

    project_path = "{0}/{1}".format(projects_path,saved_project_name)

    result_file_name = "{0}/{1}:{2}.json".format(alerts_path,repository_name, project_name)

    update_repository(git_url=git_url, project_path=project_path)

    git_repo_object = Repo(project_path)

    if saved_project_name not in status_conf:
        status_conf[saved_project_name] = {}
        update_status(project_path=project_path, saved_project_name=saved_project_name)
        is_new_project = True

    scan_project(saved_project_name=saved_project_name,
                 result_file_name=result_file_name,
                 git_url=git_url,
                 project_path=project_path,
                 is_new_project=is_new_project,
                 git_repo_object=git_repo_object,
                 repository_name=repository_name,
                 project_name=project_name)


def run_job():
    """
    Preparing repositories for scanning.

    :return:
    """
    logging.info("Starting scan job")
    config_file = open(conf_path + "repository.json", "r")
    config = json.loads(config_file.read())
    config_file.close()

    status_file_path = conf_path + 'status.json'
    if not os.path.isfile(status_file_path):
        f = open(status_file_path, 'w')
        f.write("{}")
        f.close()

    # Need to update save status after every branch scan
    status_file = open(status_file_path, "r+")
    global status_conf
    status_conf = json.load(status_file)

    for repository_name, repository_item in config.items():
        logging.info("Starting to scan repository: " + repository_name)
        if "key_name" in config[repository_name]:
            ssh_add_command = "ssh-add {0}/conf/keys/{1}".format("codeguard", config[repository_name]["key_name"])
            #ssh_add_command = "ssh-add conf/{1}".format(APP_PATH, config[repository_name]["key_location"])
            ssh_priv_pw = "{0}".format(config[repository_name]["key_password"])
            print(ssh_add_command)
            try:
                child = pexpect.spawn(ssh_add_command, encoding='utf-8')
                print(child)
                child.sendline(ssh_priv_pw)
                print(child)
                child.expect(pexpect.EOF)
                print(child)
                child.close()
                t = child.before
            except:
                print("failed to add key")

        for project_name, project_item in repository_item["projects"].items():
            try:
                init_project(repository_name=repository_name,project_name=project_name, config=config)
            except:
                logging.exception("Failed to run project: " + project_name)
                pass

    status_file.seek(0)
    status_file.truncate()
    status_file.write(json.dumps(status_conf, indent=4))
    status_file.close()
    logging.info("Finished scan job")


def main():
    """
    Main job and scheduler

    :return:
    """
    run_job()
    schedule.every(1).minutes.do(run_job)

    while True:
        schedule.run_pending()
        time.sleep(1)


if __name__== "__main__":
    main()





