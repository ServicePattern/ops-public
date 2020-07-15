#!/usr/bin/python
# ------------------------------------------------------------------------------
# Archives logs from every host in a cluster
#
# Author: Alexander Fichel
#
# Requirements:
# - boto3 installed
# - aws credentials setup to allow access to s3 bucket (list object, put object)
# - python 2.6 or 2.7
# - centos 6 or 7 with flock command (for cron job)
# ------------------------------------------------------------------------------

import argparse
import ast
import boto3
from botocore.errorfactory import ClientError
import ConfigParser
from datetime import datetime, timedelta
import dateutil
import dateutil.parser
from email.mime.text import MIMEText
from email.MIMEMultipart import MIMEMultipart
from email.mime.application import MIMEApplication
import errno
import json
import logging
from logging import handlers
import os
import sys
from sys import stdout
import smtplib
import socket
import subprocess
import time
import traceback
import zipfile

datetime_today = datetime.today()
today = datetime_today.strftime('%Y_%m_%d')

# Hard coded vars, don't change this!
LOG_FILE_NAME = 'coldstorage.log'
SUMMARY_FILE_NAME = 'coldstorage_summary_{0}.txt'.format(today)
CATALOG_NAME_S3 = 'catalog.txt'

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
    logger.setLevel(logging.INFO)
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
    parser.add_argument('--config', default='default.cfg',
        help='Specify different config file (.cfg) here')
    return parser.parse_args(args)


# Same as running bash command 'mkdir -p'
def mkdir(path, dry_run=False):
    logger = logging.getLogger()
    try:
        os.makedirs(path)
        logger.debug("New folder(s) created: {0}".format(path))
    except OSError as e:
        if errno.EEXIST != e.errno:
            raise
        logger.debug("Folder already exists: {0}".format(path))


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


def get_summary_dir():
    work_dir = os.path.dirname(os.path.abspath(sys.argv[0]))
    summary_dir = os.path.join(work_dir, 'reports')
    try:
        os.makedirs(summary_dir)
    except:
        pass
    return summary_dir


def get_summary_filepath():
    summary_dir = get_summary_dir()
    filename = SUMMARY_FILE_NAME
    fullpath = os.path.join(summary_dir, filename)
    return fullpath


def write_summary(line):
    with open(get_summary_filepath(), 'a') as f:
        f.write("{0}\n".format(line))


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
        subject='Archive logs (s3 glacier) backup failed: {0}',
        message=err_msg,
        attachment=log_path_zipped)


# Gets sent every time there is a failure
def email_success(recipients):
    try:
        summary_file_to_send = get_summary_filepath()
        with open(summary_file_to_send, 'r') as f:
            message = f.read()
    except Exception as e:
        message = 'Failed to parse summary file: {0}\n'.format(summary_file_to_send)
        message+= str(e)
        raise
    finally:
        send_email(
            recipients=recipients,
            subject='Archive logs (s3 glacier) backup successful: {0}',
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


def get_session(region_name):
    session = boto3.session.Session(region_name=region_name)
    return session


def get_client(region_name, service):
    session = get_session(region_name=region_name)
    client = session.client(service)
    return client


def get_file_s3(bucket, key):
    s3 = get_client(region_name='us-east-2', service='s3')
    return s3.get_object(Bucket=bucket, Key=key)


def get_archived_folders(target_archive_dir):
    logger = logging.getLogger()
    archived_folders = []
    logger.info("Getting local archive folders from: {0}".format(target_archive_dir))
    for d in os.listdir(target_archive_dir):
        if os.path.isdir(os.path.join(target_archive_dir, d)):
            logger.info("Detected local archive folder: {0}".format(d))
            archived_folders.append(d)
    return archived_folders


def extract_catalog_data(catalog):
    logger = logging.getLogger()
    catalog_data = []
    if catalog:
        for item in catalog['Body'].read().splitlines():
            catalog_data.append(item.strip())
    logger.info('Catalog (previously archived folders) contents: {0}'.format(catalog_data))
    return catalog_data


def is_recent(archive):
    logger = logging.getLogger()
    cutoff = datetime_today - timedelta(days=3)
    # archive must be in format of '2020-03-02' to be parseable
    datetime_archive = dateutil.parser.parse(archive)
    if datetime_archive > cutoff:
        logger.info('Archive "{0}" is newer than cutoff date {1}'.format(archive, cutoff))
        return True
    else:
        logger.info('Archive "{0}" is older than cutoff date {1}'.format(archive, cutoff))
        return False


def get_new_local_archives(local_archives, catalog_data):
    logger = logging.getLogger()
    new_local_archives = []
    for archive in local_archives:
        if archive not in catalog_data:
            new_local_archives.append(archive)
            logger.info("Add new local archive folder for syncing: {0}".format(archive))
        elif is_recent(archive):
            new_local_archives.append(archive)
            logger.info("Add recently archived folder for syncing: {0}".format(archive))
        else:
            logger.info("Skip synced archive folder: {0}".format(archive))
    return new_local_archives


# Run local command which you can use to run remote ssh commands too
def run_cmd(cmd, log_error_only=False):
    logger = logging.getLogger()
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


def upload_catalog(catalog_data, bucket, s3_prefix, target):
    logger = logging.getLogger()
    temp_catalog_file = "/tmp/{0}".format(CATALOG_NAME_S3)
    try:
        with open(temp_catalog_file, "w") as f:
            f.write("\n".join(catalog_data))
        source = temp_catalog_file
        destination = 's3://{0}/{1}/{2}/'.format(bucket, s3_prefix, target)
        cmd = 'aws s3 cp {0} {1}'.format(source, destination)
        logger.info("Attempt to upload catalog \"{0}\" to {1}".format(source, destination))
        with open(temp_catalog_file, 'r') as f:
            catalog_file_content = f.read()
            logger.info("Catalog contents: \n" + catalog_file_content)
        rc = run_cmd(cmd)
        if rc != 0:
            logger.error("Failed to upload catalog")
        else:
            logger.info("Successfully uploaded catalog")
    finally:
        try:
            os.remove(temp_catalog_file)
        except OSError as e:
            log.warning(e)


def coldstorage(args, conf):
    logger = logging.getLogger()
    # --------------------------------------------------------------------------
    # Load configs
    # --------------------------------------------------------------------------
    # Get dir where script is located to help load config
    for item in conf.items('DEFAULT'):
        logger.info("Load from config file -> {0}".format(item))
    # Assign vars to avoid long config methods
    archive_dir = conf.get('DEFAULT', 'archive_dir')
    recipients = conf.get('DEFAULT', 'recipients')
    cluster = conf.get('DEFAULT', 'cluster')
    bucket = conf.get('DEFAULT', 'bucket')
    s3_prefix = conf.get('DEFAULT', 's3_prefix')
    storage_class = conf.get('DEFAULT', 'storage_class')
    # --------------------------------------------------------------------------
    # Build target host list
    # --------------------------------------------------------------------------
    # Get all nfs mounted target log folders and apply exclude filter in case
    # you wanted to exlcude all rtp or a specific target host
    targets = os.listdir(archive_dir)
    targets.sort()
    logger.info("Found {0} valid archived target hosts in {1}".format(len(targets), archive_dir))
    logger.info('Targets are: {0}'.format(targets))
    # --------------------------------------------------------------------------
    # Begin sending to cold storage
    # --------------------------------------------------------------------------
    for target in targets:
        start_time = time.time()
        logger.info("Start cold storage backup task for {0}".format(target))
        target_archive_dir = os.path.join(archive_dir, target)
        # Get catalog of archived folders in s3
        catalog = None
        try:
            key='{0}/{1}/{2}'.format(s3_prefix, target, CATALOG_NAME_S3)
            catalog = get_file_s3(bucket, key)
        except ClientError as e:
            if e.response['Error']['Code'] == 'NoSuchKey':
                logging.info('S3 "{0}" missing key: {1}'.format(bucket, key))
            else:
                raise
        catalog_data = extract_catalog_data(catalog)
        # Get list of folders that are not in s3 glacier yet
        local_archives = get_archived_folders(target_archive_dir)
        new_local_archives = get_new_local_archives(local_archives, catalog_data)
        # Sync the folders
        try:
            for archive in new_local_archives:
                source = os.path.join(target_archive_dir, archive)
                destination = 's3://{0}/{1}/{2}/{3}'.format(bucket, s3_prefix, target, archive)
                cmd = 'aws s3 sync {0} {1} --storage-class {2}'.format(source, destination, storage_class)
                logger.info("Attempting to sync archive \"{archive}\" to s3://{bucket}/{s3_prefix}/{target}/{archive}".format(
                    archive=archive,
                    bucket=bucket,
                    s3_prefix=s3_prefix,
                    target=target))
                rc = run_cmd(cmd)
                if rc != 0:
                    logger.error("Failed to sync archive")
                    break
                logger.info("Successfully synced archive")
                if archive not in catalog_data:
                    catalog_data.append(archive)
        finally:
            end_time = time.time()
            duration = human_readable_time(end_time - start_time)
            summary = '{target}: Archived logs sent to S3 glacier cold storage (in {duration})'.format(
                target=target,
                duration=duration)
            logger.info(summary)
            write_summary(line='    {0}'.format(summary))
            upload_catalog(catalog_data, bucket, s3_prefix, target)
            logger.info('====================================================')


def main(args):
    logger = logging.getLogger()
    for arg in vars(args):
        logger.info('Script parameter -> {0} = {1}'.format(arg, getattr(args, arg)))
    conf = get_config(args=args)
    recipients = ast.literal_eval(conf.get('DEFAULT', 'recipients'))
    try:
        job_start = time.asctime()
        write_summary(line='{0}'.format(job_start))
        coldstorage(args, conf)
        logger.info('Script successful')
        write_summary(line='    [ SUCCESSFUL ]\n')
        email_success(recipients=recipients)
    except Exception as e:
        logger.info('Script failed: {0}'.format(e))
        traceback.print_exc()
        write_summary(line='    [ FAILED ]\n')
        email_failure(recipients=recipients, err_msg=str(e))


if __name__ == '__main__':
    manage_logger()
    main(parse_args(sys.argv[1:]))
