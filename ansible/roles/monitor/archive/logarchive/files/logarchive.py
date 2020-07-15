#!/usr/bin/python
# ------------------------------------------------------------------------------
# Archives logs from every host in a cluster
#
# Author: Alexander Fichel
#
# Requirements:
# - key based ssh access from archive server to all target hosts
# - archive server must have all nfs mounted target folders with logs
# - python 2.6 or 2.7
# - centos 6 or 7 with flock command (for cron job)
# ------------------------------------------------------------------------------

import argparse
import ast
import ConfigParser
from datetime import datetime
from email.mime.text import MIMEText
from email.MIMEMultipart import MIMEMultipart
from email.mime.application import MIMEApplication
import errno
import json
import logging
from logging import handlers
import os
import pprint
import re
import sys
from sys import stdout
import shutil
import smtplib
import socket
import subprocess
import time
import traceback
import zipfile

today = datetime.today().strftime('%Y_%m_%d')

# Hard coded vars, don't change this!
LOG_FILE_NAME = 'logarchive.log'
SUMMARY_FILE_NAME = 'summary_{0}.txt'.format(today)
HISTORY_FILE_NAME = 'history.dump'
SERVICEPATTERN_LOG_DIR = '/var/log/servicepattern'
TEMP_STEP_FILE_GBL = '/tmp/temp_step_file{0}.txt'
TEMP_TARGET_DIR_GBL = '/tmp/temp_dir{0}'

# Logger for the script itself, not to be confused with servicepattern logs
def manage_logger():
    work_dir = os.path.dirname(os.path.abspath(sys.argv[0]))
    log_dir = os.path.join(work_dir, 'logs')
    log_name = LOG_FILE_NAME
    log_path = os.path.join(log_dir, log_name)
    try:
        os.makedirs(log_dir)
    except:
        pass
    logger = logging.getLogger()
    logger.setLevel(logging.DEBUG)
    log_exists = os.path.isfile(log_path)
    filehandler = logging.handlers.RotatingFileHandler(log_path, backupCount=10)
    formatter = logging.Formatter('%(levelname)s %(asctime)s - %(funcName)s (line:%(lineno)d) - %(message)s')
    filehandler.setFormatter(formatter)
    logger.addHandler(filehandler)
    consolehandler = logging.StreamHandler(stdout)
    consolehandler.setFormatter(formatter)
    logger.addHandler(consolehandler)
    if log_exists:
        logger.debug('Log closed on {0}'.format(time.asctime()))
        logger.handlers[0].doRollover()
    logger.debug('Log started on {0}'.format(time.asctime()))


def parse_args(args):
    parser = argparse.ArgumentParser()
    parser.add_argument('--dry-run', action='store_true',
        help='For testing purposes, no actual logs are archived')
    parser.add_argument('--config', default='default.cfg',
        help='Specify different config file (.cfg) here')
    return parser.parse_args(args)


def load_history(history_file_path):
    logger = logging.getLogger()
    try:
        with open(history_file_path, 'r') as f:
            if os.stat(history_file_path).st_size == 0:
                logger.info('History file is empty, start fresh')
                return set()
        history = json.load(open(history_file_path))
        logger.info('Retrieved previous history on {0} logs'.format(len(history)))
        return set(history)
    except IOError as e:
        logger.info('Since there is no history for this target, start fresh')
        return set()


# Overwrites history file, does not append
def dump_history(history_file_path, history, dry_run=False):
    logger = logging.getLogger()
    if dry_run:
        logger.info("(dry_run={0}) Skip writing history in {1}".format(dry_run, history_file_path))
        return
    try:
        with open(history_file_path, 'w') as f:
           json.dump(list(history), f)
        logger.info('Write updated history to file: {0}'.format(history_file_path))
    except IOError as e:
        logger.info('No archive folder to write history too yet')


# Find all fresh logs from the target's nfs mount on the archive server
# Filters out empty logs and active logs apps are writing to
# Futhermore filters out logs that were archived before
# Returns 2 lists:
# - list of new "archivable" logs, filtering out those already archived before
# - list of all "archivable" logs
def get_target_logs(target_log_dir, history):
    logger = logging.getLogger()
    logger.info("Searching through current logs in {0}".format(target_log_dir))
    filtered_archivable_logs = []
    all_archivable_logs = []
    for f in os.listdir(target_log_dir):
        if not bool(re.match(".*[0-9].log$", f)):
            logger.debug("Skip active log: {0}".format(f))
            continue
        if f in history:
            logger.debug("Skip archived log: {0}".format(f))
            all_archivable_logs.append(f)
            continue
        try:
            if not os.stat(os.path.join(target_log_dir, f)).st_size > 0:
                logger.debug("Skip empty log: {0}".format(f))
                continue
        except OSError as e:
            logger.warning("Skip missing log: '{0}'".format(os.path.join(f)))
            continue
        logger.debug("Add: {0}".format(f))
        filtered_archivable_logs.append(f)
        all_archivable_logs.append(f)
    if not filtered_archivable_logs:
        logger.info("Could not find any new archivable logs on target")
    else:
        logger.info("Found {0} new archivable logs on target".format(len(filtered_archivable_logs)))
    return filtered_archivable_logs, all_archivable_logs


# Same as running bash command 'mkdir -p'
def mkdir(path, dry_run=False):
    logger = logging.getLogger()
    try:
        if dry_run:
            logger.info("(dry_run={0}) Attempting to create dir path {1}".format(dry_run, path))
            return
        os.makedirs(path)
        logger.debug("New folder(s) created: {0}".format(path))
    except OSError as e:
        if errno.EEXIST != e.errno:
            raise
        logger.debug("Folder already exists: {0}".format(path))


# Run local command which you can use to run remote ssh commands too
def run_cmd(cmd, log_error_only=False, dry_run=False):
    logger = logging.getLogger()
    if not log_error_only or dry_run:
        logger.info("(dry_run={0}) Run command: {1}".format(dry_run, cmd))
    if dry_run:
        return 0
    process = subprocess.Popen(
        args=cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        universal_newlines=True,
        shell=True)
    while True:
        output = process.stdout.readline()
        if logger.level == logging.DEBUG and not log_error_only:
            logger.debug('stdout - {0}'.format(output.strip()))
        rc = process.poll()
        if rc is not None:
            if rc != 0:
                logger.info("Command exited with return code: {0}".format(rc))
                for error in process.stderr.readlines():
                    logger.error('stderr - {0}'.format(error.strip()))
            else:
                # For some commands like gzip, the verbose option logs to stderr
                if logger.level == logging.DEBUG:
                    for out in process.stderr.readlines():
                        if 'Warning: Permanently added' not in out.strip():
                            logger.info('stderr - {0}'.format(out.strip()))
            return rc


# Just a wrapper for run_cmd to run remote command on target
def run_ssh_cmd(cmd, ssh_key, ssh_user, host, log_error_only=False, dry_run=False):
  ssh_cmd = ('ssh'
    ' -i {ssh_key}'
    ' -o PasswordAuthentication=no'
    ' -o StrictHostKeyChecking=no'
    ' -o UserKnownHostsFile=/dev/null'
    ' {ssh_user}@{host} {cmd}').format(
        cmd = cmd,
        ssh_key = ssh_key,
        ssh_user = ssh_user,
        host = host)
  rc = run_cmd(ssh_cmd, log_error_only=log_error_only, dry_run=dry_run)
  return rc


# Search through /etc/hosts file on archive server to get ip
def get_ip_from_hosts_file(target, hosts_file='/etc/hosts'):
    logger = logging.getLogger()
    hosts_file = hosts_file
    target_ip = None
    with open(hosts_file, 'r') as f:
        lines = f.read().splitlines()
        for line in lines:
            line = line.rstrip()
            if target in line:
                p = re.compile("^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}")
                s = re.search(pattern=p, string=line)
                if s:
                    target_ip = s.group()
                    break
    logger.info('{0} yielded ip address for {1}: {2}'.format(hosts_file, target, target_ip))
    return target_ip


# Search through /proc/mount file on archive server for mapped nfs folder name to get ip
def get_ip_from_mount_file(target_log_dir, target, mount_file='/proc/mounts'):
    logger = logging.getLogger()
    mount_file = mount_file
    target_ip = None
    # Change dir to nfs folder in case it got auto dismounted
    run_cmd('cd {0}'.format(target_log_dir), log_error_only=True)
    with open(mount_file, 'r') as f:
        for line in f:
            if target in line:
                p = re.compile(",addr=(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})")
                s = re.search(pattern=p, string=line)
                if s:
                    target_ip = s.groups()[0]
                    break
    logger.info('{0} yielded ip address for {1}: {2}'.format(mount_file, target, target_ip))
    return target_ip


# Small controller type function, in case we add more ways to get target ip
def get_target_ip(target_log_dir, target):
    logger = logging.getLogger()
    logger.info('Try to find ip address for {0}'.format(target))
    target_ip = get_ip_from_hosts_file(target)
    if not target_ip:
        target_ip = get_ip_from_mount_file(target_log_dir, target)
    return target_ip


# Compares filenames taken from "temp_step_file" after rsync is performed to
# see if they exist in the "target_archive_dir".
# Additionally it updates the history data (modifies the dict object)
def check_rsync_success(temp_step_file, target_archive_dir, history, dry_run=False):
    logger = logging.getLogger()
    files_successfully_copied_count = 0
    files_failed_copied_count = 0
    files_total = 0
    if dry_run:
        logger.info("(dry_run={0}) Skipping..".format(dry_run))
        return files_successfully_copied_count, files_failed_copied_count, files_total
    uncopied_files = []
    with open(temp_step_file, 'r') as f:
        lines = f.read().splitlines()
        for line in lines:
            if not line:
                continue
            files_total+=1
            logfile_name = line.strip()
            archived_logfile_name = line + '.gz'
            archived_logfile_path = os.path.join(target_archive_dir, archived_logfile_name)
            if os.path.isfile(archived_logfile_path):
                files_successfully_copied_count+=1
                history.add(logfile_name)
                logger.info('Added {0} to history'.format(logfile_name))
            else:
                uncopied_files.append(logfile_name)
                files_failed_copied_count+=1
    logger.info('{0} out of {1} files copied successfully'.format(
        files_successfully_copied_count,
        files_total))
    if files_failed_copied_count > 0:
        for uncopied_file in uncopied_files:
            logger.debug('Files that failed to copy: {0}'.format(uncopied_file))
    return files_successfully_copied_count, files_failed_copied_count, files_total


# Removes logs from history data if those files no longer exist on target.
# Assumes they have been archived if not present on target, otherwise it will
# take too long to compare every single archived log to see if target log was
# archived before. Keeps the history data nice and small. In practice, history
# contains running history of logs archived from previous run only and keeps them
# in history as long as they are present on the target host itself.
def purge_history(history, target_logs, dry_run=False):
    logger = logging.getLogger()
    if dry_run:
            logger.info("(dry_run={0}) Skip..".format(dry_run))
            return 0
    purged_logs_count = 0
    purged_logs_list = []
    target_logs_set = set(target_logs)
    for history_log in history.copy():
        if history_log not in target_logs_set:
            history.remove(history_log)
            purged_logs_count+=1
    if purged_logs_count > 0:
        logger.info('Successfully purged {0} stale logs from history no longer present on target'.format(purged_logs_count))
        for purged_log in purged_logs_list:
            logger.debug('Purged: {0}'.format(purged_log))
    else:
        logger.info('Did not find any stale logs to purge from history')


# Reshuffle logs into folders by date timestamp to have less files in a single folder
def folderize(target_archive_dir, dry_run=False):
    logger = logging.getLogger()
    if dry_run:
            logger.info("(dry_run={0}) Skip..".format(dry_run))
            return
    if os.path.isdir(target_archive_dir):
        folderized_count = 0
        archived_logs = [f for f in os.listdir(target_archive_dir) if re.match(".*.log.gz$", f)]
        for archived_log in archived_logs:
            logger.debug('Found non folderized archived log: {0}'.format(archived_log))
            p = re.compile(".*_(\d\d\d\d_\d\d_\d\d).*.log.gz$")
            s = re.search(pattern=p, string=archived_log)
            if s:
                date = s.groups()[0]
                logger.debug('Got {0} from log name'.format(date))
                date = date.replace('_','-')
                mkdir(os.path.join(target_archive_dir, date))
                old_path = os.path.join(target_archive_dir, archived_log)
                new_path = os.path.join(target_archive_dir, date, archived_log)
                shutil.move(old_path, new_path)
                logger.debug('Moved archived log {0} into folder {1}'.format(archived_log, date))
                folderized_count+=1
        logger.info('Folderized {0} freshly archived logs'.format(folderized_count))


def get_hostname():
    logger = logging.getLogger()
    hostname = socket.gethostname()
    logger.info('Get hostname of localhost: {0}'.format(hostname))
    return hostname


def send_email(recipients=[], subject='', message='', attachment=None):
    logger = logging.getLogger()
    hostname = get_hostname()
    short_hostname = hostname.split('.', 1)[0]
    msg = MIMEMultipart()
    msg['From'] = '"{0}"'.format(short_hostname)
    msg['To'] = (',').join(recipients)
    msg['Subject'] = subject.format(short_hostname)
    msg.attach(MIMEText(message))
    logger.debug('Prepare to send email: {0}'.format(msg))
    if attachment:
        logger.debug('Adding attachment of file: {0}'.format(attachment))
        with open(attachment, "rb") as f:
            part = MIMEApplication(f.read(), Name=os.path.basename(attachment))
            part['Content-Disposition'] = 'attachment; filename="%s"' % os.path.basename(attachment)
            msg.attach(part)
    smtp = smtplib.SMTP('localhost')
    smtp.sendmail(from_addr=hostname, to_addrs=recipients, msg=msg.as_string())
    smtp.quit()


# Gets sent every time there is a failure
def email_failure(recipients, err_msg):
    work_dir = os.path.dirname(os.path.abspath(sys.argv[0]))
    log_dir = os.path.join(work_dir, 'logs')
    log_name = LOG_FILE_NAME
    log_path = os.path.join(log_dir, log_name)
    log_path_zipped = '/tmp/{0}.zip'.format(log_name)
    zipfile.ZipFile(log_path_zipped, mode='w').write(log_path, log_name)
    send_email(
        recipients=recipients,
        subject='Log backup failed: {0}',
        message=err_msg,
        attachment=log_path_zipped)


def get_summary_filepath():
    summary_dir = get_summary_dir()
    filename = SUMMARY_FILE_NAME
    fullpath = os.path.join(summary_dir, filename)
    return fullpath


def get_summary_dir():
    work_dir = os.path.dirname(os.path.abspath(sys.argv[0]))
    summary_dir = os.path.join(work_dir, 'reports')
    try:
        os.makedirs(summary_dir)
    except:
        pass
    return summary_dir


def get_summaries():
    logger = logging.getLogger()
    summary_dir = os.path.dirname(get_summary_filepath())
    summary_files = [f for f in os.listdir(summary_dir) if re.match("summary.*", f)]
    logger.debug('Found {0} summary files in {1}'.format(len(summary_files),summary_dir))
    return [os.path.join(get_summary_dir(), summary_file) for summary_file in summary_files]


# Gets sent daily
def email_summary(recipients):
    successful_jobs = 0
    total_jobs = 0
    summary_files = get_summaries()
    summary_files.sort(reverse=True)
    summary_file_to_send = None
    if len(summary_files) > 1:
        summary_file_to_send = summary_files[1]
    if summary_file_to_send:
        day = '<date>'
        summary_file_name = os.path.basename(summary_file_to_send)
        p = re.compile(".*_(\d\d\d\d_\d\d_\d\d).txt$")
        s = re.search(pattern=p, string=summary_file_name)
        if s:
            day = s.groups()[0].replace('_','/')
        try:
            with open(summary_file_to_send, 'r') as f:
                message = f.read()
                p = re.compile("SUCCESSFUL")
                listOfMatches = p.findall(message)
                successful_jobs = len(listOfMatches)
                p = re.compile("FAILED")
                listOfMatches = p.findall(message)
                failed_jobs = len(listOfMatches)
        except Exception as e:
            message = 'Failed to parse summary file: {0}\n'.format(summary_file_to_send)
            message+= str(e)
            raise
        finally:
            send_email(
                recipients=recipients,
                subject='Log backup daily summary for {day}: {{0}} ({successful_jobs}/{total_jobs} jobs successful)'.format(
                    day=day,
                    successful_jobs=successful_jobs,
                    total_jobs=successful_jobs+failed_jobs),
                message=message)


def get_config(args):
    work_dir = os.path.dirname(os.path.abspath(sys.argv[0]))
    # Load config from file which is always in same dir as script
    config_file_path = os.path.join(work_dir, args.config)
    config = ConfigParser.ConfigParser()
    with open(config_file_path) as f:
        config.readfp(f)
    return config


def human_readable_time(sec_elapsed):
    h = int(sec_elapsed / (60 * 60))
    m = int((sec_elapsed % (60 * 60)) / 60)
    s = sec_elapsed % 60.
    return "{0} hours {1} mins {2:.2f} secs".format(h, m, s)


def write_summary(line):
    with open(get_summary_filepath(), 'a') as f:
        f.write("{0}\n".format(line))


def archive(args, conf):
    logger = logging.getLogger()
    # --------------------------------------------------------------------------
    # Load configs
    # --------------------------------------------------------------------------
    # Get dir where script is located to help load config
    for item in conf.items('DEFAULT'):
        logger.info("Load from config file -> {0}".format(item))
    # Assign vars to avoid long config methods
    log_dir = conf.get('DEFAULT', 'log_dir')
    archive_dir = conf.get('DEFAULT', 'archive_dir')
    exclude_targets = conf.get('DEFAULT', 'exclude_targets')
    step = conf.getint('DEFAULT', 'step')
    ssh_user = conf.get('DEFAULT', 'ssh_user')
    ssh_key = conf.get('DEFAULT', 'ssh_key')
    bwlimit = conf.get('DEFAULT', 'bwlimit')
    recipients = conf.get('DEFAULT', 'recipients')
    cluster = conf.get('DEFAULT', 'cluster')
    # --------------------------------------------------------------------------
    # Build target host list
    # --------------------------------------------------------------------------
    # Load exclude patterns filter
    exc_list = ast.literal_eval(exclude_targets)
    # Get all nfs mounted target log folders and apply exclude filter in case
    # you wanted to exlcude all rtp or a specific target host
    targets = [t for t in os.listdir(log_dir)
        if not any(re.compile(x).match(t) for x in exc_list)]
    targets.sort()
    logger.info("Found {0} valid target hosts in {1}".format(len(targets), log_dir))
    logger.info('Targets are: {0}'.format(targets))
    # --------------------------------------------------------------------------
    # Begin archiving
    # --------------------------------------------------------------------------
    TEMP_STEP_FILE = TEMP_STEP_FILE_GBL.format(cluster)
    TEMP_TARGET_DIR = TEMP_TARGET_DIR_GBL.format(cluster)
    for target in targets:
        start_time = time.time()
        try:
            final_files_successfully_copied_count = 0
            final_files_failed_copied_count = 0
            final_files_total = 0
            logger.info("Start archive task for {0}".format(target))
            # Get history of logs already processed on previous runs
            history_file_path = os.path.join(archive_dir, target, HISTORY_FILE_NAME)
            history = load_history(history_file_path)
            target_log_dir = os.path.join(log_dir, target)
            target_archive_dir = os.path.join(archive_dir, target)
            target_ip = get_target_ip(target_log_dir, target)
            if not target_ip:
                logger.info("Skipping target, missing ip address for {0}".format(target))
                continue
            # Get list of logs to archive from target
            target_logs, target_logs_including_archived = get_target_logs(target_log_dir, history)
            if len(history) != 0:
                purge_history(history, target_logs_including_archived, dry_run=args.dry_run)
            if len(target_logs) == 0:
                logger.info("Skipping target, no new archivable logs found for: {0}".format(target))
                continue
            # Break down list of logs into smaller chunks
            sliced_target_logs = [target_logs[i:i+step] for i in range(0, len(target_logs), step)]
            logger.info(('Sliced {number_of_new_logs} total new logs into'
                ' {number_of_slices} smaller slice(s) of {slice_size}'
                ' max logs each (remaining slice is {last_slice_size} logs)').format(
                    number_of_new_logs=len(target_logs),
                    number_of_slices=len(sliced_target_logs),
                    slice_size=step,
                    last_slice_size=len(sliced_target_logs[-1])))
            # Make sure archive folder for the target host exists on monitor server
            mkdir(target_archive_dir, dry_run=args.dry_run)
            # Break down all the archivable logs into smaller slices
            slice_count = 1
            for slice in sliced_target_logs:
                logger.info("Attempt to archive logs for slice {0} out of {1} total slices".format(
                    slice_count,
                    len(sliced_target_logs)))
                # Create a file with the logs from this slice
                if args.dry_run:
                    logger.info("(dry_run={0}) Creating temp file of slice of logs in {1}".format(
                        args.dry_run,
                        TEMP_STEP_FILE))
                else:
                    with open(TEMP_STEP_FILE, 'w') as f:
                        logger.info("Create temp file with slice of logs: {0}".format(TEMP_STEP_FILE))
                        for log_name in slice:
                            f.write("{0}\n".format(log_name))
                    with open(TEMP_STEP_FILE, 'r') as f:
                        logger.debug("Contents of temp file:\n{0}".format(f.read()))
                copy_cmd = ('scp'
                    ' -i {ssh_key}'
                    ' -o PasswordAuthentication=no'
                    ' -o StrictHostKeyChecking=no'
                    ' -o UserKnownHostsFile=/dev/null'
                    ' -r {source} {ssh_user}@{host}:{destination}').format(
                        source=TEMP_STEP_FILE,
                        ssh_user=ssh_user,
                        ssh_key=ssh_key,
                        host=target_ip,
                        destination=TEMP_STEP_FILE)
                rc = run_cmd(copy_cmd, log_error_only=True, dry_run=args.dry_run)
                if rc != 0:
                    logger.error(("Skipping target, could not copy temp"
                        " file to remote target: {0} ({1})").format(target, target_ip))
                    break
                logger.info('Successfully copied over the temp file to target: {0}'.format(target))
                rc = run_ssh_cmd(
                    cmd = 'mkdir -p {0}'.format(TEMP_TARGET_DIR),
                    ssh_key=ssh_key,
                    ssh_user=ssh_user,
                    host=target_ip,
                    log_error_only=True,
                    dry_run=args.dry_run)
                if rc != 0:
                    logger.error(("Skipping target, could not create temp dir"
                        " to store zipped logs on remote target: {0} ({1})").format(target, target_ip))
                    break
                logger.info('Successfully created temp dir on remote target')
                rc = run_ssh_cmd(
                    cmd = ('\'set {trace};'
                           'for file in $(cat {temp_step_file});'
                           '    do gzip -c{verbose} {servicepattern_log_dir}/$file > {temp_target_dir}/$file.gz;'
                           '    touch -d \"$(date -R -r {servicepattern_log_dir}/$file)\" \"{temp_target_dir}/$file.gz\";'
                           'done\'').format(
                                trace='-x' if logger.level == logging.DEBUG else '+x',
                                temp_step_file=TEMP_STEP_FILE,
                                servicepattern_log_dir=SERVICEPATTERN_LOG_DIR,
                                verbose='v' if logger.level == logging.DEBUG else '',
                                temp_target_dir=TEMP_TARGET_DIR),
                    ssh_key=ssh_key,
                    ssh_user=ssh_user,
                    host=target_ip,
                    dry_run=args.dry_run)
                if rc != 0:
                    logger.error("Skipping target, could not zip log files on remote target: {0} ({1})".format(target, target_ip))
                    break
                logger.info('Successfully gzip(ed) logs on target from list in {0}'.format(TEMP_STEP_FILE))
                rsync_cmd = ('rsync -arhv'
                    ' --bwlimit={bwlimit}'
                    ' --progress'
                    ' -e "ssh -i {ssh_key}'
                    ' -o PasswordAuthentication=no'
                    ' -o StrictHostKeyChecking=no'
                    ' -o UserKnownHostsFile=/dev/null"'
                    ' {ssh_user}@{host}:{temp_target_dir}/'
                    ' {target_archive_dir}/').format(
                        bwlimit=bwlimit,
                        ssh_key=ssh_key,
                        ssh_user=ssh_user,
                        host=target_ip,
                        temp_target_dir=TEMP_TARGET_DIR,
                        target_archive_dir=target_archive_dir)
                rc = run_cmd(rsync_cmd, dry_run=args.dry_run)
                if rc != 0:
                    logger.error("Skipping target, could not rsync zipped logs from remote target: {0} ({1})".format(target, target_ip))
                    break
                logger.info('Successfully rsync(ed) the archived log files from remote temp dir to archive server')
                rc = run_ssh_cmd(
                    cmd = 'find {0} -type f -name "*.log.gz" -delete'.format(TEMP_TARGET_DIR),
                    ssh_key=ssh_key,
                    ssh_user=ssh_user,
                    host=target_ip,
                    log_error_only=True,
                    dry_run=args.dry_run)
                if rc != 0:
                    logger.error("Failed to clean up files on remote target destination")
                    break
                logger.info("Successfully cleaned up files on remote target destination")
                logger.info('Verify if all files were successfully copied')
                # Check if file was actually copied and records it in the history
                files_successfully_copied_count, files_failed_copied_count, files_total = check_rsync_success(
                    TEMP_STEP_FILE,
                    target_archive_dir,
                    history,
                    dry_run=args.dry_run)
                final_files_successfully_copied_count+=files_successfully_copied_count
                final_files_failed_copied_count+=files_failed_copied_count
                final_files_total+=files_total
                slice_count+=1
        finally:
            dump_history(history_file_path, history, dry_run=args.dry_run)
            # Folderize the files to correct log_archive folder
            folderize(target_archive_dir, dry_run=args.dry_run)
            end_time = time.time()
            duration = human_readable_time(end_time - start_time)
            summary = '{target}: {files_copied} of {files_total} archived (in {duration})'.format(
                target=target,
                files_copied=final_files_successfully_copied_count,
                files_total=final_files_total,
                duration=duration)
            logger.info(summary)
            write_summary(line='    {0}'.format(summary))
            logger.info('====================================================')


# Handle all errors, cleanups, emails here
def main(args):
    logger = logging.getLogger()
    for arg in vars(args):
        logger.info('Script parameter -> {0} = {1}'.format(arg, getattr(args, arg)))
    conf = get_config(args=args)
    recipients = ast.literal_eval(conf.get('DEFAULT', 'recipients'))
    try:
        summary_dry_run = ''
        if args.dry_run:
            summary_dry_run = '(--dry-run = True)'
        starting_summary_file_count = len(get_summaries())
        job_start = time.asctime()
        write_summary(line='{0} {1}'.format(job_start, summary_dry_run))
        archive(args, conf)
        logger.info('Script successful')
        write_summary(line='    [ SUCCESSFUL ]\n')
    except Exception as e:
        logger.info('Script failed: {0}'.format(e))
        traceback.print_exc()
        write_summary(line='    [ FAILED ]\n')
        email_failure(recipients=recipients, err_msg=str(e))
        raise
    finally:
        ending_summary_file_count = len(get_summaries())
        # This will effectively send out email summaries every 24 hours, since
        # summaries are generated by adding YY-MM-DD to the file name, thus they
        # rotate every 24 hours
        if ending_summary_file_count != starting_summary_file_count:
            email_summary(recipients=recipients)


if __name__ == '__main__':
    manage_logger()
    main(parse_args(sys.argv[1:]))

#TODO Add rate limit to rsync
