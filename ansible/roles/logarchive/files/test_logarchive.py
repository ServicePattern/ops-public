#!/usr/bin/python
# ------------------------------------------------------------------------------
# This was getting to big of a script to not write small unit tests
#
# Author: Alexander Fichel
#
# Run tests:
#
# $ cd /path/to/test_logarchive.py
# $ pytest -v
# ------------------------------------------------------------------------------

import logarchive
import pytest
import pprint
import os
import logging

logging.basicConfig(
    level=logging.DEBUG,
    format='%(levelname)s %(asctime)s - %(funcName)s (line:%(lineno)d) - %(message)s')

def get_obj_attrs(obj):
    attrs = dir(obj)
    for attr in attrs:
        print(attr)


def test_load_history(tmp_path):
    # Test when there is no history file present
    history = logarchive.load_history('/path/not/found/history.dump')
    assert history == set([])
    # Test when history file is empty
    d = tmp_path / "test1"
    d.mkdir()
    p = d / "history.dump"
    history = logarchive.load_history(str(p.absolute()))
    assert history == set([])
    # Test when history file is not empty
    content = u'["a_2020_05_02_08_08_14.log", "b_2020_05_04_16_42_14.log"]'
    d = tmp_path / "test2"
    d.mkdir()
    p = d / "history.dump"
    p.write_text(content)
    history = logarchive.load_history(str(p.absolute()))
    assert len(history) == 2


def test_dump_history(tmp_path):
    # Test dumping empty history
    d = tmp_path / "test1"
    d.mkdir()
    p = d / "history.dump"
    history_file_path = str(p.absolute())
    history = set([])
    logarchive.dump_history(history_file_path, history)
    assert p.read_text() == '[]'
    # Test dumping some history
    history = set(["a_2020_05_02_08_08_14.log", "b_2020_05_04_16_42_14.log"])
    logarchive.dump_history(history_file_path, history)
    assert p.read_text() == '["a_2020_05_02_08_08_14.log", "b_2020_05_04_16_42_14.log"]'


def test_get_target_logs(tmp_path):
    with pytest.raises(OSError):
        filtered_archivable_logs, all_archivable_logs = logarchive.get_target_logs(
            target_log_dir='/path/not/found/target/',
            history=set([]))
    d = tmp_path / "test_target_1"
    d.mkdir()
    # Target with no logs
    filtered_archivable_logs, all_archivable_logs = logarchive.get_target_logs(
        target_log_dir=str(d),
        history=set([]))
    assert filtered_archivable_logs == []
    assert all_archivable_logs == []
    p1 = d / "agentserver_2020_04_29_18_01_14.log"
    p1.write_text(u'')
    p2 = d / "cfgsrv_2020_05_02_09_58_14.log"
    p2.write_text(u'')
    p3 = d / "smsserver.log"
    p3.write_text(u'')
    p4 = d / "goodlog_2020_05_02_09_58_15.log"
    p4.write_text(u'abc')
    # No history provided
    history = set([])
    filtered_archivable_logs, all_archivable_logs = logarchive.get_target_logs(
        target_log_dir=str(d),
        history=history)
    assert filtered_archivable_logs == ['goodlog_2020_05_02_09_58_15.log']
    assert all_archivable_logs == ['goodlog_2020_05_02_09_58_15.log']
    # History provided
    history = set(['goodlog_2020_05_02_09_58_15.log'])
    filtered_archivable_logs, all_archivable_logs = logarchive.get_target_logs(
        target_log_dir=str(d),
        history=history)
    assert filtered_archivable_logs == []
    assert all_archivable_logs == ['goodlog_2020_05_02_09_58_15.log']


def test_get_ip_from_hosts_file(tmp_path):
    d = tmp_path / "etc"
    d.mkdir()
    p = d / "hosts"
    p.write_text((
        u'127.0.0.1       localhost localhost.localdomain localhost4 localhost4.localdomain4\n'
        u'::1             localhost localhost.localdomain localhost6 localhost6.localdomain6\n'
        u'\n'
        u'10.15.0.15      peakint1.brightpattern.com          peakint1\n'
        u'10.15.0.16      peakdmz1-int.brightpattern.com      peakdmz1-int\n'
        u'\n'
        u'10.13.0.40      peakrtp4-int.brightpattern.com      peakrtp4-int\n'
        u'32.253.88.50    peakdmz1-priv.brightpattern.com'))
    assert logarchive.get_ip_from_hosts_file('peakdmz1', hosts_file=str(p)) == '10.15.0.16'
    assert logarchive.get_ip_from_hosts_file('peakdmz5') is None
    p.write_text((
        u'127.0.0.1       localhost localhost.localdomain localhost4 localhost4.localdomain4\n'
        u'::1             localhost localhost.localdomain localhost6 localhost6.localdomain6\n'
        u'\n'
        u'172.17.0.227   japarb.bp.local                 japarb\n'
        u'172.17.1.203   japarb-priv.brightpattern.com   japarb-priv\n'
        u'\n'
        u'172.17.0.39    japdb1.bp.local                 japdb1\n'
        u'172.17.1.62    japdb1-priv.brightpattern.com   japdb1-priv'))
    assert logarchive.get_ip_from_hosts_file('japdb1', hosts_file=str(p)) == '172.17.0.39'
    p.write_text((
        u'127.0.0.1       localhost localhost.localdomain localhost4 localhost4.localdomain4\n'
        u'::1             localhost localhost.localdomain localhost6 localhost6.localdomain6\n'
        u'\n'
        u'#10.252.0.6      ausrtp1.bp.local                    ausrtp1\n'
        u'#10.252.0.61     ausdmz2.bp.local                    ausdmz2\n'
        u'\n'
        u'10.252.0.6      ausrtp1-int.brightpattern.com                    ausrtp1-int    ausrtp1.bp.local\n'
        u'10.252.0.12     ausdmz1-int.brightpattern.com                    ausdmz1-int    ausdmz1.bp.local'))
    assert logarchive.get_ip_from_hosts_file('ausrtp1', hosts_file=str(p)) == '10.252.0.6'
    assert logarchive.get_ip_from_hosts_file('ausdmz2', hosts_file=str(p)) is None
    assert logarchive.get_ip_from_hosts_file('ausdmz1', hosts_file=str(p)) == '10.252.0.12'


def test_get_ip_from_mount_file(tmp_path):
    d = tmp_path / "proc"
    d.mkdir()
    p = d / "mounts"
    p.write_text((
        u'rootfs / rootfs rw 0 0'
        u'\ndevpts /dev/pts devpts rw,seclabel,nosuid,noexec,relatime,gid=5,mode=620,ptmxmode=000 0 0'
        u'\npeakdmz1-int:/usr/lib/servicepattern/logs /mnt/logs/peakdmz1 nfs ro,relatime,vers=3,rsize=1048576,wsize=1048576,namlen=255,hard,proto=tcp,timeo=600,retrans=2,sec=sys,mountaddr=10.15.0.16,mountvers=3,mountport=20048,mountproto=udp,local_lock=none,addr=10.15.0.16 0 0'
        u'\npeakdmz2-int:/usr/lib/servicepattern/logs /mnt/logs/peakdmz2 nfs ro,relatime,vers=3,rsize=1048576,wsize=1048576,namlen=255,hard,proto=tcp,timeo=600,retrans=2,sec=sys,mountaddr=10.15.0.21,mountvers=3,mountport=892,mountproto=udp,local_lock=none,addr=10.15.0.21 0 0'
        u'\n10.19.0.1:/Users/test/Projects/vagrant/simple/shared on /vagrant type nfs (rw,relatime,vers=3,rsize=8192,wsize=8192,namlen=255,hard,proto=udp,timeo=11,retrans=3,sec=sys,mountaddr=10.19.0.1,mountvers=3,mountport=878,mountproto=udp,local_lock=none,addr=10.19.0.1)'
        u'\n10.19.0.20:/var/log/servicepattern on /mnt/logs/simple2 type nfs4 (rw,relatime,vers=4.1,rsize=65536,wsize=65536,namlen=255,hard,proto=tcp,timeo=600,retrans=2,sec=sys,clientaddr=10.19.0.10,local_lock=none,addr=10.19.0.20)'
        u'\nausdmz1-int:/usr/lib/servicepattern/logs on /mnt/logs/ausdmz1 type nfs (ro,relatime,vers=3,rsize=1048576,wsize=1048576,namlen=255,hard,proto=tcp,timeo=600,retrans=2,sec=sys,mountaddr=10.252.0.12,mountvers=3,mountport=20048,mountproto=udp,local_lock=none,addr=10.252.0.12)'
    ))
    assert logarchive.get_ip_from_mount_file(str(d), 'peakdmz1', mount_file=str(p)) == '10.15.0.16'
    assert logarchive.get_ip_from_mount_file(str(d), 'peakdmz2', mount_file=str(p)) == '10.15.0.21'
    assert logarchive.get_ip_from_mount_file(str(d), 'peakdmz3', mount_file=str(p)) is None
    assert logarchive.get_ip_from_mount_file(str(d), 'simple2', mount_file=str(p)) == '10.19.0.20'
    assert logarchive.get_ip_from_mount_file(str(d), 'simple1', mount_file=str(p)) is None
    assert logarchive.get_ip_from_mount_file(str(d), 'ausdmz1', mount_file=str(p)) == '10.252.0.12'


def test_check_rsync_success(tmp_path):
    d = tmp_path / "test1"
    d.mkdir()
    tmp_step_file = d / "temp_file.txt"
    tmp_step_file.write_text((
        u'agentserver_2020_04_29_18_01_14.log\n'
        u'cfgsrv_2020_05_02_09_58_14.log\n'
        u'goodlog_2020_05_02_09_58_15.log\n'
        u'missinglog_2020_05_04_09_58_15.log\n'))
    temp_step_file = str(tmp_step_file)
    darchive = tmp_path / "test_target_1"
    darchive.mkdir()
    p1 = darchive / "agentserver_2020_04_29_18_01_14.log.gz"
    p1.write_text(u'abc')
    p2 = darchive / "cfgsrv_2020_05_02_09_58_14.log.gz"
    p2.write_text(u'abc')
    p3 = darchive / "goodlog_2020_05_02_09_58_15.log.gz"
    p3.write_text(u'abc')
    target_archive_dir = str(darchive)
    # Test 1
    history = set([])
    s, f, t = logarchive.check_rsync_success(temp_step_file, target_archive_dir, history)
    assert s == 3
    assert f == 1
    assert t == 4
    assert len(history) == 3
    # Test 2 (when temp file does not contains anything)
    tmp_step_file.write_text((u''))
    s, f, t = logarchive.check_rsync_success(temp_step_file, target_archive_dir, history)
    assert s == 0
    assert f == 0
    assert t == 0
    assert len(history) == 3
    # Test 3 (when no logs were copied, history has some records)
    darchive = tmp_path / "test_target_2"
    darchive.mkdir()
    target_archive_dir = str(darchive)
    tmp_step_file.write_text((
        u'agentserver_2020_04_29_18_01_14.log\n'
        u'cfgsrv_2020_05_02_09_58_14.log\n'
        u'goodlog_2020_05_02_09_58_15.log\n'
        u'missinglog_2020_05_04_09_58_15.log\n'))
    s, f, t = logarchive.check_rsync_success(temp_step_file, target_archive_dir, history)
    assert s == 0
    assert f == 4
    assert t == 4
    assert len(history) == 3
    # Test 4 (when no logs were copied, history empty)
    history = set([])
    s, f, t = logarchive.check_rsync_success(temp_step_file, target_archive_dir, history)
    assert len(history) == 0
    # Test 5 (temp file empty, no logs copied, no history)
    tmp_step_file.write_text((u''))
    history = set([])
    darchive = tmp_path / "test_target_3"
    darchive.mkdir()
    target_archive_dir = str(darchive)
    s, f, t = logarchive.check_rsync_success(temp_step_file, target_archive_dir, history)
    assert s == 0
    assert f == 0
    assert t == 0
    assert len(history) == 0


def test_purge_history():
    history = set(["a_2020_05_02_08_08_14.log", "b_2020_05_04_16_42_14.log"])
    target_logs = ['1.log', '2.log', '3.log']
    logarchive.purge_history(history, target_logs)
    assert len(history) == 0
    history = set(["a_2020_05_02_08_08_14.log", "b_2020_05_04_16_42_14.log"])
    target_logs = ['1.log', '2.log', 'b_2020_05_04_16_42_14.log']
    logarchive.purge_history(history, target_logs)
    assert len(history) == 1
    history = set([])
    target_logs = []
    logarchive.purge_history(history, target_logs)
    assert len(history) == 0
    history = set([])
    target_logs = ['1.log']
    logarchive.purge_history(history, target_logs)
    assert len(history) == 0
    history = set(['1.log'])
    target_logs = ['1.log']
    logarchive.purge_history(history, target_logs)
    assert len(history) == 1
    history = set([])
    target_logs = ['1.log']
    logarchive.purge_history(history, target_logs)
    assert len(history) == 0
    history = set([1,2,3,4,5])
    target_logs = [1,2,3]
    logarchive.purge_history(history, target_logs)
    assert len(history) == 3
    history = set([1,2,3,4,5])
    target_logs = [6,7,8,1]
    logarchive.purge_history(history, target_logs)
    assert len(history) == 1


def test_folderize(tmp_path):
    darchive = tmp_path / "test_target_1"
    darchive.mkdir()
    target_archive_dir = str(darchive)
    logarchive.folderize(target_archive_dir)
    dirs = os.listdir(target_archive_dir)
    assert len(dirs) == 0
    p1 = darchive / "agentserver_2020_04_29_18_01_14.log.gz"
    p1.write_text(u'abc')
    p2 = darchive / "cfgsrv_2020_05_02_09_58_14.log.gz"
    p2.write_text(u'abc')
    p3 = darchive / "goodlog_2020_05_02_09_58_15.log.gz"
    p3.write_text(u'abc')
    logarchive.folderize(target_archive_dir)
    dirs = os.listdir(target_archive_dir)
    assert len(dirs) == 2
    assert set(dirs) == set(['2020_04_29', '2020_05_02'])
    logs1 = os.listdir(os.path.join(target_archive_dir, '2020_04_29'))
    logs2 = os.listdir(os.path.join(target_archive_dir, '2020_05_02'))
    assert len(logs1) == 1
    assert logs1[0] == 'agentserver_2020_04_29_18_01_14.log.gz'
    assert set(logs2) == set(['cfgsrv_2020_05_02_09_58_14.log.gz', 'goodlog_2020_05_02_09_58_15.log.gz'])
