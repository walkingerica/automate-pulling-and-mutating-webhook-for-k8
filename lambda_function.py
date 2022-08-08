import json
import base64
from functools import reduce
import boto3
from botocore.exceptions import ClientError
import os

ecr = boto3.client('ecr')
dynamodb = boto3.resource('dynamodb')
tab = dynamodb.Table(os.environ["DDB_TABLE_NAME"])
project_name = os.environ["G_PROJECT_NAME"]
secret_name = os.environ['GLOBAL_AKSK']



image_mirrors = {
    "k8s.gcr.io/":
    "<Your account>.dkr.ecr.cn-north-1.amazonaws.com.cn/gcr/google_containers/",
    "gcr.io/google-containers/":
    "<Your account>.dkr.ecr.cn-north-1.amazonaws.com.cn/gcr/google_containers/",
    "gcr.io/": "<Your account>.dkr.ecr.cn-north-1.amazonaws.com.cn/gcr/",
}


def handler(event, context):

    request_body = json.loads(event['body'])
    json_patch = []

    # get initContainers from request and replace image path with JSON Patch
    initContainers = dict_get(request_body,
                              'request.object.spec.initContainers')
    if initContainers:
        json_patch += image_patch(initContainers, '/spec/initContainers')

    # get containters from request and replace image path with JSON Patch
    containers = dict_get(request_body, 'request.object.spec.containers')
    if containers:
        json_patch += image_patch(containers, '/spec/containers')

    print(json.dumps(json_patch))
    # set response body
    patch_b64 = base64.b64encode(
        json.dumps(json_patch).encode("utf-8")).decode("utf-8")
    response_body = {
        'kind': 'AdmissionReview',
        'apiVersion': 'admission.k8s.io/v1',
        'response': {
            'uid': dict_get(request_body, 'request.uid'),
            'allowed': True,
            'patch': patch_b64,
            'patchType': 'JSONPatch'
        }
    }

    return {
        'body': json.dumps(response_body),
        'headers': {
            'Content-Type': 'application/json'
        },
        'statusCode': 200
    }


def dict_get(dictionary, keys, default=None):
    return reduce(
        lambda d, key: d.get(key, default) if isinstance(d, dict) else default,
        keys.split("."), dictionary)


def replace_dockerhub_prfix(image):
    if image.startswith("library/"):
        return image[len("library/"):]
    elif image.startswith("docker.io/"):
        return image.replace("docker.io/library/",
                             "").replace("docker.io/", "")

def get_secret():

    # Create a Secrets Manager client
    secret_client = boto3.client(service_name='secretsmanager')
 #   client = session.client(
 #       service_name='secretsmanager',
 #       region_name=china_region_name
 #   )

    try:
        get_secret_value_response = secret_client.get_secret_value(
            SecretId=secret_name
        )
        print(get_secret_value_response)
    except ClientError as e:
        if e.response['Error']['Code'] == 'ResourceNotFoundException':
            print("The requested secret " + secret_name + " was not found")
        elif e.response['Error']['Code'] == 'InvalidRequestException':
            print("The request was invalid due to:", e)
        elif e.response['Error']['Code'] == 'InvalidParameterException':
            print("The request had invalid params:", e)
        elif e.response['Error']['Code'] == 'DecryptionFailure':
            print("The requested secret can't be decrypted using the provided KMS key:", e)
        elif e.response['Error']['Code'] == 'InternalServiceError':
            print("An error occurred on service side:", e)
    else:
        # Secrets Manager decrypts the secret value using the associated KMS CMK
        # Depending on whether the secret was a string or binary, only one of these field
        if 'SecretString' in get_secret_value_response:
            secret = get_secret_value_response['SecretString']
            return json.loads(secret)
        else:
            secret = base64.b64decode(get_secret_value_response['SecretBinary'])
            return json.loads(secret)


def create_codebuild(docker_image, new_docker_image):

    credentials = get_secret()
    print(credentials)

    global_region = credentials['G_AWS_REGION']
    global_access_key = credentials['G_ACCESS_KEY']
    global_secret_key = credentials['G_SECRET_KEY']

    codebuild = boto3.client(
            'codebuild',
            region_name=global_region,
            aws_access_key_id=global_access_key,
            aws_secret_access_key=global_secret_key)

    try:
        print('docker_image %s, new_docker_image %s.'
                        % (docker_image, new_docker_image))

        try:
            resp = tab.put_item(
                Item={
                    'repo': new_docker_image.split(':')[0],
                    'tag': new_docker_image.split(':')[1]
                },
                ConditionExpression=
                'attribute_not_exists(repo) AND attribute_not_exists(tag)'
                )
        except ClientError as e:
            if e.response['Error'][
                    'Code'] == 'ConditionalCheckFailedException':  # If the DDB item exists there will be a started build
                print(
                    "The item exists and the there should be a existed build!")
                return
            else:
                print("DDB put item unkown error!")
                print(e)


        codebuild.start_build(projectName=project_name,
                              environmentVariablesOverride=[{
                                  "name": "DOCKER_IMAGE",
                                  "value": docker_image,
                                  "type": "PLAINTEXT"
                              }, {
                                  "name": "NEW_DOCKER_IMAGE",
                                  "value": new_docker_image,
                                  "type": "PLAINTEXT"
                              }])
    except ClientError as e:
        print("Start global codebuild project error!")
        print(e)


def image_patch(containers, path_prefix):
    json_patch = []
    for idx, container in enumerate(containers):
        image = container['image']
        docker_image = image
        math_mirror = False
        for orig_image, mirror_image in image_mirrors.items():
            if image.startswith(orig_image):
                math_mirror = True
                image = mirror_image + image[len(orig_image):]
                print('Image %s' % (image))

        if "/" in image_mirrors and math_mirror == False:

            if image.startswith("docker.io/") or image.startswith("library/"):
                math_mirror = True
                image = image_mirrors["/"] + replace_dockerhub_prfix(image)

            elif "." not in image.split("/")[0]:
                math_mirror = True
                image = image_mirrors["/"] + image
        if math_mirror:
            ecr_prefix = image.split("/")[0]

            if ('sha256' in image) and (len(image.split(':')) < 3):
                image = image.replace("@sha256:", ":sha256-")
            else:
                image = image.replace("@sha256:", "-sha256-")
            ecr_repo = '/'.join(image.split(":")[0].split("/")[1:])
            ecr_tag = (image.split(":")[1]
                       if len(image.split(":")) > 1 else "latest")
            new_docker_image = '%s/%s:%s' % (ecr_prefix, ecr_repo, ecr_tag)

            try:
                ecr_images = ecr.list_images(repositoryName=ecr_repo)
                match_tag = False
                for i in ecr_images['imageIds']:
                    if i["imageTag"] == ecr_tag:
                        match_tag = True

                if match_tag:
                    print('Image %s:%s exists!' % (ecr_repo, ecr_tag))
                else:
                    print(
                        'Image tag %s for %s not exists! Start the global codebuild.'
                        % (ecr_tag, ecr_repo))
                    create_codebuild(docker_image, new_docker_image)

            except ClientError as e:
                if e.response['Error'][
                        'Code'] == 'RepositoryNotFoundException':
                    try:
                        print('Repo Not Found, create the new Repo: %s' %
                              (ecr_repo))
                        ecr.create_repository(repositoryName=ecr_repo)
                        print('Start image tag %s for %s global codebuild!' %
                              (ecr_tag, ecr_repo))
                        create_codebuild(docker_image, new_docker_image)
                    except ClientError as e1:
                        print("Create repo error or submit build job error!")
                        print(e1)
                else:
                    print('List repo images error!')
                    print(e)

            json_patch.append({
                'op': 'replace',
                'path': '%s/%d/image' % (path_prefix, idx),
                'value': new_docker_image
            })
    return json_patch
