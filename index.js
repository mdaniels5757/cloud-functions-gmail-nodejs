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

'use strict';

const { google } = require('googleapis');
const gmail = google.gmail('v1');
const querystring = require('querystring');
const config = require('./config');
const oauth = require('./lib/oauth');
const helpers = require('./lib/helpers');

/**
 * Request an OAuth 2.0 authorization code
 * Only new users (or those who want to refresh
 * their auth data) need visit this page
 */
exports.oauth2init = (req, res) => {
  // Define OAuth2 scopes
  const scopes = [
    'https://www.googleapis.com/auth/gmail.readonly'
  ];

  // Generate + redirect to OAuth2 consent form URL
  const authUrl = oauth.client.generateAuthUrl({
    access_type: 'offline',
    scope: scopes,
    prompt: 'consent' // Required in order to receive a refresh token every time
  });
  return res.redirect(authUrl);
};

/**
 * Get an access token from the authorization code and store token in Datastore
 */
exports.oauth2callback = (req, res) => {
  // Get authorization code from request
  const code = req.query.code;
  console.error('In oauth2callback:51');
  // OAuth2: Exchange authorization code for access token
  return new Promise((resolve, reject) => {
    console.error('In oauth2callback:54');
    oauth.client.getToken(code, (err, token) =>
      (err ? reject(err) : resolve(token))
    );
  }, (err) => {
    // Handle error
    console.error(err);
    console.error('In oauth2callback:61');
    res.status(500).send('Something went wrong; check the logs.');
  })
    .then((token) => {
      console.error('In oauth2callback:64');
      // Get user email (to use as a Datastore key)
      oauth.client.credentials = token;
      const promiseTemp = Promise.all([token, oauth.getEmailAddress()]);
      console.error('In oauth2callback:68');
      return promiseTemp;
    }, (err) => {
      // Handle error
      console.error(err);
      console.error('In oauth2callback:74');
      res.status(500).send('Something went wrong; check the logs.');
    })
    .then(([token, emailAddress]) => {
      // Store token in Datastore
      console.error('In oauth2callback:77');
      const promiseTemp = Promise.all([
        emailAddress,
        oauth.saveToken(emailAddress)
      ]);
      console.error('In oauth2callback:82');
      console.error('promiseTemp = ' + promiseTemp);
      return promiseTemp;
    } /*, (err) => {
      // Handle error
      console.error(err);
      console.error('In oauth2callback:90');
      res.status(500).send('Something went wrong; check the logs.');
    } */)
    .then((val) => { // Was [emailAddress], then [emailAddress, _] instead of val
      // Respond to request
      console.error('In oauth2callback:92');
      console.error('val = ' + val);
      // res.redirect(`/initWatch?emailAddress=${querystring.escape(val[0])}`);
      console.error('In oauth2callback:95');
    } /*, (err) => {
      // Handle error
      console.error(err);
      console.error('In oauth2callback:102');
      res.status(500).send('Something went wrong; check the logs.');
    } */)
    .catch((err) => {
      // Handle error
      console.error(err);
      console.error('In oauth2callback:108');
      res.status(500).send('Something went wrong; check the logs.');
    });
};

/**
 * Initialize a watch on the user's inbox
 */
exports.initWatch = (req, res) => {
  // Require a valid email address
  if (!req.query.emailAddress) {
    return res.status(400).send('No emailAddress specified.');
  }
  const email = querystring.unescape(req.query.emailAddress);
  if (!email.includes('@')) {
    return res.status(400).send('Invalid emailAddress.');
  }

  // Retrieve the stored OAuth 2.0 access token
  return oauth.fetchToken(email)
    .then(async () => {
      // Initialize a watch
      return await gmail.users.watch({
        auth: oauth.client,
        userId: 'me',
        resource: {
          topicName: config.TOPIC_NAME
        }
      });
    })
    .then(() => {
      // Respond with status
      res.write('Watch initialized!');
      res.status(200).end();
    })
    .catch((err) => {
      // Handle errors
      if (err.message === config.UNKNOWN_USER_MESSAGE) {
        res.redirect('/oauth2init');
      } else {
        console.error(err);
        res.status(500).send('Something went wrong; check the logs.');
      }
    });
};

exports.listLabels = (req, res) => {
  // Require a valid email address
  if (!req.query.emailAddress) {
    return res.status(400).send('No emailAddress specified.');
  }
  const email = querystring.unescape(req.query.emailAddress);
  if (!email.includes('@')) {
    return res.status(400).send('Invalid emailAddress.');
  }

  // Retrieve the stored OAuth 2.0 access token
  return oauth.fetchToken(email)
    .then(async () => {
      const labelsResponse = await gmail.users.labels.list({
        userId: 'me'
      });
      const labels = labelsResponse.data.labels;
      if (!labels || labels.length === 0) {
        res.write('No labels found.');
      } else {
        res.write('Labels:');
        labels.forEach((label) => {
          res.write(`- ${label.name}`);
        });
      }
      res.status(200).end();
    })
    .catch((err) => {
      // Handle errors
      if (err.message === config.UNKNOWN_USER_MESSAGE) {
        res.redirect('/oauth2init');
      } else {
        console.error(err);
        res.status(500).send('Something went wrong; check the logs.');
      }
    });
};

/**
* Process new messages as they are received
*/
exports.onNewMessage = (event) => {
  // Parse the Pub/Sub message
  const dataStr = Buffer.from(event.data.data, 'base64').toString('ascii');
  const dataObj = JSON.parse(dataStr);

  return oauth.fetchToken(dataObj.emailAddress)
    .then(helpers.listMessageIds)
    .then(res => helpers.getMessageById(res.messages[0].id)) // Most recent message
    .then(msg => {
      // TODO: do something
      // if (msg.)
    })
    .catch((err) => {
      // Handle unexpected errors
      if (!err.message || err.message !== config.NO_LABEL_MATCH) {
        console.error(err);
      }
    });
};
