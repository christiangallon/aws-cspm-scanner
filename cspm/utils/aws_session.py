import boto3


def get_session(
    profile: str | None = None, role_arn: str | None = None, session_name: str = "cspm-session"
):
    base_session = boto3.Session(profile_name=profile) if profile else boto3.Session()

    if not role_arn:
        return base_session

    sts = base_session.client("sts")

    response = sts.assume_role(RoleArn=role_arn, RoleSessionName=session_name)

    credentials = response["Credentials"]

    return boto3.Session(
        aws_access_key_id=credentials["AccessKeyId"],
        aws_secret_access_key=credentials["SecretAccessKey"],
        aws_session_token=credentials["SessionToken"],
    )
