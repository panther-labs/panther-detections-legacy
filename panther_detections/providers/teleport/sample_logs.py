import json

nmap_with_no_args = json.dumps(
    {
        "argv": [],
        "cgroup_id": 4294967672,
        "code": "T4000I",
        "ei": 16,
        "event": "session.command",
        "login": "root",
        "namespace": "default",
        "path": "/bin/nmap",
        "pid": 13555,
        "ppid": 13525,
        "program": "nmap",
        "return_code": 0,
        "server_id": "e75992b4-9e27-456f-b1c9-7a32da83c661",
        "sid": "a3562a0e-e57f-4273-9f69-eedb6cd029cb",
        "time": "2020-08-17T21:13:47.117Z",
        "uid": "c7f6367b-04bb-4b1d-9a3a-0497e8f4a650",
        "user": "panther",
    }
)
netcat_command = json.dumps(
    {
        "argv": ["-l", "-p", "11434"],
        "cgroup_id": 4294967537,
        "code": "T4000I",
        "ei": 15,
        "event": "session.command",
        "login": "root",
        "namespace": "default",
        "path": "/bin/nc",
        "pid": 7143,
        "ppid": 7115,
        "program": "nc",
        "return_code": 0,
        "server_id": "e75992b4-9e27-456f-b1c9-7a32da83c661",
        "sid": "8a3fc038-785b-43f3-8737-827b3e25fe5b",
        "time": "2020-08-17T17:40:37.491Z",
        "uid": "8eaf8f39-09d4-4a42-a22a-65163d2af702",
        "user": "panther",
    }
)
crontab_list = json.dumps(
    {
        "argv": ["-l"],
        "cgroup_id": 4294967582,
        "code": "T4000I",
        "ei": 37,
        "event": "session.command",
        "login": "root",
        "namespace": "default",
        "path": "/bin/crontab",
        "pid": 9330,
        "ppid": 9315,
        "program": "crontab",
        "return_code": 0,
        "server_id": "e75992b4-9e27-456f-b1c9-7a32da83c661",
        "sid": "af24d0b8-9767-4bd8-99ce-7a4449ee3eba",
        "time": "2020-08-17T18:50:39.1Z",
        "uid": "6b463839-c641-43d3-ab97-3137ff9b09f8",
        "user": "panther",
    }
)
nmap_with_args = json.dumps(
    {
        "argv": ["-v", "-iR", "100000", "-Pn", "-p", "80"],
        "cgroup_id": 4294967672,
        "code": "T4000I",
        "ei": 16,
        "event": "session.command",
        "login": "root",
        "namespace": "default",
        "path": "/bin/nmap",
        "pid": 13555,
        "ppid": 13525,
        "program": "nmap",
        "return_code": 0,
        "server_id": "e75992b4-9e27-456f-b1c9-7a32da83c661",
        "sid": "a3562a0e-e57f-4273-9f69-eedb6cd029cb",
        "time": "2020-08-17T21:13:47.117Z",
        "uid": "c7f6367b-04bb-4b1d-9a3a-0497e8f4a650",
        "user": "panther",
    }
)
crontab_edit = json.dumps(
    {
        "argv": ["-e"],
        "cgroup_id": 4294967582,
        "code": "T4000I",
        "ei": 50,
        "event": "session.command",
        "login": "root",
        "namespace": "default",
        "path": "/bin/crontab",
        "pid": 9451,
        "ppid": 9217,
        "program": "crontab",
        "return_code": 0,
        "server_id": "e75992b4-9e27-456f-b1c9-7a32da83c661",
        "sid": "af24d0b8-9767-4bd8-99ce-7a4449ee3eba",
        "time": "2020-08-17T18:54:32.273Z",
        "uid": "ad4a31d0-d739-4409-8f1c-cf573ed97a89",
        "user": "panther",
    }
)
ssh_errors = json.dumps(
    {
        "code": "T3007W",
        "error": 'ssh: principal "jack" not in the set of valid principals for given certificate: ["ec2-user"]',
        "event": "auth",
        "success": False,
        "time": "2020-08-13T18:39:42Z",
        "uid": "53e474cc-db1c-45f1-a60d-b31239e20098",
        "user": "panther",
    }
)
crontab_no_args = json.dumps(
    {
        "argv": [],
        "cgroup_id": 4294967717,
        "code": "T4000I",
        "ei": 39,
        "event": "session.command",
        "login": "root",
        "namespace": "default",
        "path": "/bin/crontab",
        "pid": 18415,
        "ppid": 18413,
        "program": "crontab",
        "return_code": 0,
        "server_id": "e073ecab-6091-45da-83e4-80196e7bc659",
        "sid": "29a3d18c-2c05-453d-979a-2ed888a14788",
        "time": "2020-08-18T00:05:12.465Z",
        "uid": "83e88438-efbc-41a2-8135-b0157e0d14c0",
        "user": "panther",
    }
)
userdel_command = json.dumps(
    {
        "argv": ["jacknew"],
        "cgroup_id": 4294967567,
        "code": "T4000I",
        "ei": 105,
        "event": "session.command",
        "login": "root",
        "namespace": "default",
        "path": "/sbin/userdel",
        "pid": 8931,
        "ppid": 8930,
        "program": "userdel",
        "return_code": 0,
        "server_id": "e75992b4-9e27-456f-b1c9-7a32da83c661",
        "sid": "4244c271-8069-4679-a27e-f7c18f88ce45",
        "time": "2020-08-17T18:39:26.192Z",
        "uid": "346d3f61-a010-4871-84de-897f50b18118",
        "user": "panther",
    }
)
echo_command = json.dumps(
    {
        "argv": [],
        "cgroup_id": 4294967537,
        "code": "T4000I",
        "ei": 15,
        "event": "session.command",
        "login": "root",
        "namespace": "default",
        "path": "/bin/echo",
        "pid": 7143,
        "ppid": 7115,
        "program": "echo",
        "return_code": 0,
        "server_id": "e75992b4-9e27-456f-b1c9-7a32da83c661",
        "sid": "8a3fc038-785b-43f3-8737-827b3e25fe5b",
        "time": "2020-08-17T17:40:37.491Z",
        "uid": "8eaf8f39-09d4-4a42-a22a-65163d2af702",
        "user": "panther",
    }
)
nmap_running_from_crontab = json.dumps(
    {
        "cgroup_id": 4294967792,
        "code": "T4002I",
        "dst_addr": "67.205.137.100",
        "dst_port": 1723,
        "ei": 32,
        "event": "session.network",
        "login": "root",
        "namespace": "default",
        "pid": 15412,
        "program": "nmap",
        "server_id": "e75992b4-9e27-456f-b1c9-7a32da83c661",
        "sid": "a3562a0e-e57f-4273-9f69-eedb6cd029cb",
        "src_addr": "172.31.9.159",
        "time": "2020-08-18T17:37:35.883Z",
        "uid": "3e067d21-a5fb-47a3-af09-e6b9da39753c",
        "user": "panther",
        "version": 4,
    }
)
