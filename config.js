/**
 * Copyright 2018, Google LLC
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

// Configuration constants
const GCF_REGION = process.env.GCF_REGION;
const GCLOUD_PROJECT = process.env.GCLOUD_PROJECT;
const TOPIC_ID = process.env.TOPIC_ID;

// Computed values
exports.GCF_BASE_URL = `https://${GCF_REGION}-${GCLOUD_PROJECT}.cloudfunctions.net`;
exports.TOPIC_NAME = `projects/${GCLOUD_PROJECT}/topics/${TOPIC_ID}`;
exports.GCF_REGION = GCF_REGION;
exports.GCLOUD_PROJECT = GCLOUD_PROJECT;

// Constants
exports.NO_LABEL_MATCH = 'Message doesn\'t match label';
exports.UNKNOWN_USER_MESSAGE = 'Uninitialized email address';
