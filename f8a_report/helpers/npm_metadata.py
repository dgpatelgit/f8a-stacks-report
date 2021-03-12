# Copyright © 2020 Red Hat Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# Author: Dharmendra G Patel <dhpatel@redhat.com>
#
"""Class to update NPM package details."""
import io
import json
import requests
import logging as logger
from helpers.s3_helper import S3Helper

logger.basicConfig(level=logger.INFO)
# logger = logging.getLogger(__file__)

DEV_MODE_ON = False

NPM_PACKAGE_FILE_PATH = "training-utils/node-package-details-with-url.json"
NPM_PACKAGE_FILE_PATH_NEW = "training-utils/node-package-details.json"

NPM_LOCAL_MANIFEST_FILE_PATH = \
    "/home/dhpatel/Downloads/prod-s3-cvae-npm-insights_2020-07-20/data/manifest.json"
NPM_LOCAL_PACKAGE_FILE_PATH = \
    "/home/dhpatel/Downloads/prod-s3-cvae-npm-insights_training-utils" \
    "/node-package-details-with-url.json"
NPM_LOCAL_PACKAGE_FILE_PATH_NEW = \
    "/home/dhpatel/Downloads/prod-s3-cvae-npm-insights_training-utils/node-package-details.json"


class NPMMetadata:
    """NPM metadata fetcher."""

    def __init__(self, s3Helper=S3Helper, github_token=str,
                 bucket_name=str, manifest_data=dict()):
        """Set obect default memebers."""
        self.s3Helper = s3Helper
        self.github_token = github_token
        self.bucket_name = bucket_name
        self.package_list = self._flatten_list(manifest_data)
        self.existing_data = self._get_transform_data()

        self.stats = {
            'existing_count': len(self.existing_data),
            'unique_manifest_count': len(self.package_list),
            'metadata_exists': 0,
            'total_missing': 0,
            'new_packages': 0,
            'updated_count': 0,
            'still_missing': 0,
            'fetched_from_npm': 0,
            'fetched_from_github': 0,
            'npm_fetch_errors': 0,
            'github_fetch_errors': 0,
        }

    def update(self):
        """Read and update metadata for all NPM packages in S3."""
        logger.info("Existing node package length: %d", self.stats['existing_count'])
        logger.info("Number of node package in manifest: %d", self.stats['unique_manifest_count'])

        '''topN = 10
        for p, v in self.existing_data.items():
            logger.info("v: %s", v)
            topN -= 1
            if topN == 0:
                break'''

        topN = 50
        for package_name in self.package_list:
            package_keyword_list = self.existing_data.get(package_name, None)
            if not package_keyword_list or \
               type(package_keyword_list.get("keywords", None)) != list or \
               len(package_keyword_list.get("keywords", [])) == 0:
                logger.info("Keywords are missing or empty for '%s' finding it from the "
                            "repository / github.", package_name)
                self.stats['total_missing'] += 1

                if not package_keyword_list:
                    self.stats['new_packages'] += 1

                package_details = self._fetch(package_name)
                if package_details:
                    logger.info("New package '%s' has keywords %s",
                                package_details['name'],
                                package_details['keywords'])
                    self.stats['updated_count'] += 1
                else:
                    self.stats['still_missing'] += 1

                    self.existing_data[package_name] = package_details

                topN -= 1
                if topN == 0:
                    break
            else:
                self.stats['metadata_exists'] += 1

        self._transform_and_save_data()
        self._print_stats()

    def _print_stats(self):
        """Print statistics about operation."""
        logger.info("NPM Metadata update statistics")
        logger.info("    1. Existing number of NPM packages : %d", self.stats['existing_count'])
        logger.info("    2. Unique packages in manifest : %d", self.stats['unique_manifest_count'])
        logger.info("    3. Packages with metadata : %d", self.stats['metadata_exists'])
        logger.info("    4. Total missing packages : %d", self.stats['total_missing'])
        logger.info("    5. New packages : %d", self.stats['new_packages'])
        logger.info("    6. Packages updated : %d", self.stats['updated_count'])
        logger.info("    7. Packages missing after update : %d", self.stats['still_missing'])
        logger.info("    8. Data fetched from registry : %d", self.stats['fetched_from_npm'])
        logger.info("    9. Registry fetch errors : %d", self.stats['npm_fetch_errors'])
        logger.info("   10. Data fetched from github : %d", self.stats['fetched_from_github'])
        logger.info("   11. Github fetch errors : %d", self.stats['github_fetch_errors'])

    def _fetch(self, package_name=str):
        """Fetch metadata for a package and return it as json."""
        logger.info("Finding metadata for npm package '%s'", package_name)
        package_metadata = self._from_npm_registry(package_name)

        # If key words are not found in repository, get it from github.
        if package_metadata and len(package_metadata.get("keywords", [])) == 0 and \
           len(package_metadata.get("repositoryurl", "")) > 0:
            logger.info("Trying to fetch keywords from Github for '%s'", package_name)

            package_metadata["keywords"] = self._from_github(package_metadata["repositoryurl"])

        return package_metadata

    def _flatten_list(self, manifest_data):
        """Create a flatten list for given list of list."""
        package_dict = manifest_data.get("package_dict", {})
        package_list = package_dict.get("user_input_stack", []) + \
            package_dict.get("bigquery_data", [])
        flatten_package_list = [m for sub_list in package_list for m in sub_list if len(m) > 0]
        unique_flatten_package_list = list(set(flatten_package_list))
        logger.info("Found total %d packages and unque %d packages in manifest file",
                    len(package_list), len(unique_flatten_package_list))
        return unique_flatten_package_list

    def _get_transform_data(self):
        """Load the node registry dump from S3 bucket and tranform into dict for quick access."""
        if DEV_MODE_ON:
            data = {}
            try:
                with open(NPM_LOCAL_PACKAGE_FILE_PATH, "rb") as fp:
                    coded_data = fp.read().decode("utf-8")
                    io_data = io.StringIO(coded_data)
                    json_data = io_data.readlines()
                    raw_data = list(map(json.loads, json_data))
                    for package in raw_data:
                        package_name = package.get("name", None)
                        if package_name:
                            data[package_name] = package
            except Exception as e:
                logger.warn('Parsing warning raises %s, Trying to read plain json format.', e)
                with open(NPM_LOCAL_PACKAGE_FILE_PATH, "r") as fp:
                    data = json.load(fp)

            return data

        return self.s3Helper.read_json_object(bucket_name=self.bucket_name,
                                              obj_key=NPM_PACKAGE_FILE_PATH) or {}

    def _transform_and_save_data(self):
        """Get back data into original format and save it to a file."""
        if DEV_MODE_ON:
            with open(NPM_LOCAL_PACKAGE_FILE_PATH_NEW, "w+") as fp:
                json.dump(self.existing_data, fp)

        else:
            self.s3Helper.store_json_content(content=self.existing_data,
                                             bucket_name=self.bucket_name,
                                             obj_key=NPM_PACKAGE_FILE_PATH_NEW)

    def _get_org_package_name(self, repo_url):
        """Give the Query Parameters which are organization and package name respectively."""
        org = ""
        package_name = ""
        try:
            url_chunks = (repo_url.rsplit('/', 2))
            if 'github' not in url_chunks[1]:
                org = url_chunks[1]
            package_name = url_chunks[2]
            return org, package_name
        except Exception as e:
            logger.error("Could not as org and package name for repo %s, it throws error %s",
                         repo_url, e)

        return org, package_name

    def _github_clean_response(self, response_json):
        """Clean the api response json."""
        topic_edges = response_json["data"]["organization"]["repository"]["repositoryTopics"]
        topic_names = [i.get("node", {}).get("topic", {}).get("name", None)
                       for i in topic_edges["edges"]]
        topic_names = [i for i in topic_names if i is not None]
        logger.info("github found keywords: %s", topic_names)
        return topic_names

    def _from_github(self, repo_url=str):
        """Find the keywords from the Github Graph QL."""
        github_org, package_name = self._get_org_package_name(repo_url)
        api_url = "https://api.github.com/graphql"
        payload = {
            "query": "query{organization(login:\"" + github_org + "\")"
                     "{name url repository(name:\"" + package_name + "\")"
                     "{name url description repositoryTopics(first: 10)"
                     "{edges {node{topic{name}}}}}}}"
        }
        headers = {"Authorization": "token %s" % self.github_token}
        try:
            logger.info("Getting keywords from githhub for org: %s and package: %s",
                        github_org, package_name)
            response = requests.post(url=api_url, json=payload, headers=headers)
            logger.info("github response code for '%s' => %d", package_name, response.status_code)
            keywords = list(self._github_clean_response(response.json()))
            self.stats['fetched_from_github'] += 1
            return keywords
        except Exception as e:
            self.stats['github_fetch_errors'] += 1
            logger.warning("Github token missing / response is not coming, it throws %s", e)

        return []

    def _from_npm_registry(self, package_name=str):
        """Find the keywords from NPM registry(through api)."""
        data_dict = None
        api_url = "https://registry.npmjs.org/" + str(package_name)
        try:
            response = requests.get(api_url)
            logger.info("npm registry url '%s' gave reponse code %d", api_url, response.status_code)

            json_data = response.json()
            latest_version = json_data.get("dist-tags", {}).get("latest", None)
            logger.info("Found latest version %s for package %s", latest_version, package_name)
            if latest_version:
                latest_version_data = json_data.get("versions", {}).get(latest_version, {})
                data_dict = {
                    "name": json_data.get("name", ""),
                    "description": json_data.get("description", ""),
                    "version": latest_version,
                    "keywords": latest_version_data.get("keywords", []),
                    "dependencies":
                        list(latest_version_data.get("dependencies", {}).keys()),
                    "devDependencies":
                        list(latest_version_data.get("devDependencies", {}).keys()),
                    "peerDependencies":
                        list(latest_version_data.get("peerDependencies", {}).keys()),
                    "homepage": json_data.get("homepage", ""),
                    "repositoryurl": json_data.get("repository", {}).get("url", ""),
                    "readme": json_data.get("readme", ""),
                }
                self.stats['fetched_from_npm'] += 1
        except Exception as e:
            self.stats['npm_fetch_errors'] += 1
            logger.error("Can't fetch the keywords from NPM Registry, it throws %s", e)

        return data_dict


if __name__ == "__main__":
    manifest_data = {}
    with open(NPM_LOCAL_MANIFEST_FILE_PATH, "r", encoding="utf-8") as fp:
        manifest_data = json.loads(fp.read())
        logger.info(f"Size of manifest file is: {len(manifest_data)}")

    github_token = "26d8795b286ecca44f975135873cba61362e3ecf"
    s3_bucket_name = "dhpatel-cvae-insights"

    npmMetaData = NPMMetadata(None, github_token, s3_bucket_name, manifest_data)
    npmMetaData.update()
    '''npmMetaData.fetch("github", "pug-loader")
    npmMetaData.fetch("github", "express-config")
    npmMetaData.fetch("github", "express")
    npmMetaData.fetch("github", "dirty-uuid")
    npmMetaData.fetch("gnutls", "nettle")'''
