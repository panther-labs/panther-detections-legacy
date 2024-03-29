import json

rts_session_start_event = json.dumps(
    {
        "cid": "12345abcdef",
        "unknown_payload": {
            "AgentIdString": "12ab56cd",
            "CustomerIdString": "1234",
            "EventType": "Event_ExternalApiEvent",
            "ExternalApiType": "Event_RemoteResponseSessionStartEvent",
            "HostnameField": "John Macbook Pro",
            "Nonce": -4714046577736361000,
            "SessionId": "6e1181e4-4924-4761-az3d-666851jdb950",
            "StartTimestamp": 1670460538,
            "UTCTimestamp": 1670460538000,
            "UserName": "example@example.io",
            "cid": "12345abcdef",
            "eid": 118,
            "timestamp": "2022-12-08T00:48:58Z",
        },
    }
)
low_severity_finding = json.dumps(
    {
        "cid": "11111111111111111111111111111111",
        "Technique": "PUP",
        "ProcessId": 377077835340488700,
        "AgentIdString": "00000000000000000000000000000000",
        "DetectName": "NGAV",
        "ComputerName": "macbook",
        "ProcessStartTime": "2021-09-18 20:38:51Z",
        "GrandparentCommandLine": "/sbin/launchd",
        "MACAddress": "aa-00-00-00-00-00",
        "CommandLine": "/Applications/app.app/Contents/MacOS/pup app",
        "Objective": "Falcon Detection Method",
        "Nonce": 1,
        "SHA256String": "3333333333333333333333333333333333333333333333333333333333333333",
        "ExternalApiType": "Event_DetectionSummaryEvent",
        "PatternDispositionValue": 2176,
        "DetectId": "ldt:00000000000000000000000000000000:222222222222222222",
        "Severity": 2,
        "PatternDispositionDescription": "Prevention/Quarantine, process was blocked from execution and quarantine was attempted.",  # pylint: disable=C0301
        "SeverityName": "Low",
        "MD5String": "33333333333333333333333333333333",
        "EventUUID": "33333333333333333333333333333333",
        "UserName": "bobert",
        "FilePath": "/Applications/app.app/Contents/MacOS/",
        "timestamp": "2021-09-18 20:38:52Z",
        "ParentCommandLine": "/usr/libexec/runningboardd",
        "DetectDescription": "This file is classified as Adware/PUP based on its SHA256 hash.",
        "LocalIP": "192.168.1.1",
        "ProcessEndTime": "1970-01-01 00:00:00Z",
        "SHA1String": "0000000000000000000000000000000000000000",
        "OriginSourceIpAddress": "",
        "GrandparentImageFileName": "/sbin/launchd",
        "MachineDomain": "",
        "ParentImageFileName": "/usr/libexec/runningboardd",
        "FalconHostLink": "https://falcon.us-2.crowdstrike.com/activity/detections/detail/00000000000000000000000000000000/222222222222222222?",  # pylint: disable=C0301
        "UTCTimestamp": "2021-09-18 20:38:52Z",
        "FileName": "pup app",
        "ParentProcessId": 376330001421757630,
        "EventType": "Event_ExternalApiEvent",
        "CustomerIdString": "11111111111111111111111111111111",
        "Tactic": "Malware",
        "SensorId": "00000000000000000000000000000000",
        "eid": 118,
        "PatternDispositionFlags": '{\n  "BlockingUnsupportedOrDisabled": false,\n  "BootupSafeguardEnabled": false,\n  "CriticalProcessDisabled": false,\n  "Detect": false,\n  "FsOperationBlocked": false,\n  "HandleOperationDowngraded": false,\n  "InddetMask": false,\n  "Indicator": false,\n  "KillActionFailed": false,\n  "KillParent": false,\n  "KillProcess": false,\n  "KillSubProcess": false,\n  "OperationBlocked": false,\n  "PolicyDisabled": false,\n  "ProcessBlocked": true,\n  "QuarantineFile": true,\n  "QuarantineMachine": false,\n  "RegistryOperationBlocked": false,\n  "Rooting": false,\n  "SensorOnly": false,\n  "SuspendParent": false,\n  "SuspendProcess": false\n}',  # pylint: disable=C0301
    }
)
rts_session_not_started = json.dumps(
    {
        "cid": "12345abcdef",
        "unknown_payload": {
            "AgentIdString": "12ab56cd",
            "CustomerIdString": "1234",
            "EventType": "Event_ExternalApiEvent",
            "ExternalApiType": "Event_RemoteResponseSessionEndEvent",
            "HostnameField": "John Macbook Pro",
            "Nonce": -4714046577736361000,
            "SessionId": "6e1181e4-4924-4761-az3d-666851jdb950",
            "StartTimestamp": 1670460538,
            "UTCTimestamp": 1670460538000,
            "UserName": "example@example.io",
            "cid": "12345abcdef",
            "eid": 118,
            "timestamp": "2022-12-08T00:48:58Z",
        },
    }
)
denylisted_domain = json.dumps(
    {
        "event_simpleName": "DnsRequest",
        "name": "DnsRequestMacV1",
        "aid": "00000000000000000000000000000001",
        "aip": "111.111.111.111",
        "cid": "00000000000000000000000000000002",
        "id": "11111111-0000-1111-0000-111111111111",
        "event_platform": "Mac",
        "timestamp": "2021-10-01 00:00:00.000Z",
        "ConfigBuild": "1007.4.0014301.11",
        "ConfigStateHash": "507116305",
        "Entitlements": "15",
        "ContextThreadId": "0",
        "ContextTimeStamp": "2021-10-08 19:55:04.448Z",
        "ContextProcessId": "111111111111111111",
        "EffectiveTransmissionClass": 2,
        "DomainName": "baddomain.com",
        "RequestType": "1",
        "p_event_time": "2021-10-08 19:55:04.448Z",
        "p_parse_time": "2021-10-08 20:09:41.933Z",
        "p_log_type": "Crowdstrike.DNSRequest",
        "p_row_id": "2ed00000000000000000000000000001",
        "p_source_id": "11111111-1111-1111-1111-111111111111",
        "p_source_label": "Crowdstrike",
        "p_any_ip_addresses": ["111.111.111.111"],
        "p_any_domain_names": ["baddomain.com"],
        "p_any_trace_ids": [
            "00000000000000000000000000000001",
            "00000000000000000000000000000002",
        ],
    }
)
non_denylisted_domain = json.dumps(
    {
        "event_simpleName": "DnsRequest",
        "name": "DnsRequestMacV1",
        "aid": "00000000000000000000000000000001",
        "aip": "111.111.111.111",
        "cid": "00000000000000000000000000000002",
        "id": "11111111-0000-1111-0000-111111111111",
        "event_platform": "Mac",
        "timestamp": "2021-10-01 00:00:00.000Z",
        "ConfigBuild": "1007.4.0014301.11",
        "ConfigStateHash": "507116305",
        "Entitlements": "15",
        "ContextThreadId": "0",
        "ContextTimeStamp": "2021-10-08 19:55:04.448Z",
        "ContextProcessId": "111111111111111111",
        "EffectiveTransmissionClass": 2,
        "DomainName": "gooddomain.com",
        "RequestType": "1",
        "p_event_time": "2021-10-08 19:55:04.448Z",
        "p_parse_time": "2021-10-08 20:09:41.933Z",
        "p_log_type": "Crowdstrike.DNSRequest",
        "p_row_id": "2ed00000000000000000000000000001",
        "p_source_id": "11111111-1111-1111-1111-111111111111",
        "p_source_label": "Crowdstrike",
        "p_any_ip_addresses": ["111.111.111.111"],
        "p_any_domain_names": ["gooddomain.com"],
        "p_any_trace_ids": [
            "00000000000000000000000000000001",
            "00000000000000000000000000000002",
        ],
    }
)
