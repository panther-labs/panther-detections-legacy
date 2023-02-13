from panther_sdk import PantherEvent, schema


def client_port_from_alb_log(event: PantherEvent) -> int:
    return int(event.deep_get("clientPort") or 0)


def aws_alb() -> schema.DataModel:
    return schema.DataModel(
        data_model_id="aws.alb.model",
        name="AWS ALB Model",
        log_type=schema.LogTypeAWSALB,
        mappings=[
            schema.DataModelMapping(
                name="src_ip",
                path="clientIp",
            ),
            schema.DataModelMapping(
                name="dest_port",
                path="$.targetPort",
            ),
            schema.DataModelMapping(
                name="src_port",
                func=client_port_from_alb_log,
            ),
        ],
    )
