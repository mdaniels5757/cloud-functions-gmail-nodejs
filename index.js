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
const config = require('./config');
const oauth = require('./lib/oauth');
const gmail = google.gmail({ version: 'v1', auth: oauth.client });
const querystring = require('querystring');
const bunyan = require('bunyan');
const { LoggingBunyan } = require('@google-cloud/logging-bunyan');
const loggingBunyan = new LoggingBunyan({
  redirectToStdout: true,
  skipParentEntryForCloudRun: true
});
const logger = bunyan.createLogger({
  name: 'gmail-notifier',
  src: true,
  streams: [
    loggingBunyan.stream('debug')
  ]
});

/**
 * Request an OAuth 2.0 authorization code
 * Only new users (or those who want to refresh
 * their auth data) need visit this page
 */
exports.oauth2init = (_, res) => {
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
  // OAuth2: Exchange authorization code for access token
  oauth.client.getToken(code)
    .then((r) => {
      oauth.client.setCredentials(r.tokens);
    })
    .then(() => {
      // Get user email (to use as a Datastore key)
      return gmail.users.getProfile({
        auth: oauth.client,
        userId: 'me'
      });
    })
    .then((profile) => profile.data.emailAddress)
    .then((emailAddress) => {
      // Store token in Datastore
      return Promise.all([
        emailAddress,
        oauth.saveToken(emailAddress)
      ]);
    })
    .then(([emailAddress, _]) => {
      // Respond to request
      logger.info({ entry: 'Log initialized for ' + emailAddress });
      res.redirect(`/initWatch?emailAddress=${querystring.escape(emailAddress)}`);
    })
    .catch((err) => {
      // Handle error
      logger.error({ entry: err });
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
    .then(() => {
      // Initialize a watch
      return gmail.users.watch({
        auth: oauth.client,
        userId: email,
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
        logger.error({ entry: err });
        res.status(500).send('Something went wrong; check the logs.');
      }
    });
};

// NOT private: anyone can access the label info.
exports.listLabels = (req, res) => {
  const createDOMPurify = require('dompurify');
  const { JSDOM } = require('jsdom');
  const window = new JSDOM('').window;
  const DOMPurify = createDOMPurify(window);

  // Require a valid email address
  if (!req.query.emailAddress) {
    return res.status(400).send('No emailAddress specified.');
  }
  const email = querystring.unescape(req.query.emailAddress);
  if (!email.includes('@')) {
    return res.status(400).send('Invalid emailAddress.');
  }

  // Retrieve the stored OAuth 2.0 access token.
  return oauth.fetchToken(email)
    .then(async () => {
      const labelsResponse = await gmail.users.labels.list({
        userId: email
      });

      const labels = labelsResponse.data.labels;

      if (!labels || labels.length === 0) {
        res.write('No labels found.');
      } else {
        res.write('Labels:');
        res.write('<table>');
        res.write('<tr><th>label</th><th>id</th></tr>');

        labels.forEach((label) => {
          res.write(`<tr><td>${DOMPurify.sanitize(label.name)}</td><td>${DOMPurify.sanitize(label.id)}</td></tr>`);
        });
        res.write('</table>');
      }
      res.status(200).end();
    })
    .catch((err) => {
      // Handle errors
      if (err.message === config.UNKNOWN_USER_MESSAGE) {
        res.redirect('/oauth2init');
      } else {
        logger.error({ entry: err });
        res.status(500).send('Something went wrong; check the logs.');
      }
    });
};

/**
* Process new messages as they are received
*/
exports.onNewMessage = (event) => {
  logger.info({ entry: 'New event!' });
  logger.debug({ entry: 'Raw event:\n' + JSON.stringify(event, null, 4) });

  // Parse the Pub/Sub message
  const eventDataStr = Buffer.from(event.data, 'base64').toString('ascii');
  const eventDataObj = JSON.parse(eventDataStr);

  logger.debug({ entry: 'Decoded event :\n' + JSON.stringify(eventDataObj, null, 4) });
  logger.debug({ entry: 'Decoded event history ID:\n' + eventDataObj.historyId });
  logger.debug({ entry: 'Typeof Decoded event history ID:\n' + typeof eventDataObj.historyId });

  const emailAddress = eventDataObj.emailAddress;
  oauth.fetchToken(emailAddress)
    .then(() => {
      return gmail.users.messages.list({
        userId: emailAddress,
        includeSpamTrash: true,
        maxResults: 10
      });
    })
    .then(async (list) => {
      logger.debug({ entry: 'list: ' + list });
      logger.debug({ entry: 'pretty list: ' + JSON.stringify(list, null, 4) });
      for (const msgFromList of list.data.messages) {
        const msgOrNull = await gmail.users.messages.get({
          userId: emailAddress,
          id: msgFromList.id
        })
          .then((fullMsg) => {
            logger.debug({ entry: 'fullMsg is now ' + JSON.stringify(fullMsg, null, 4) });
            logger.debug({ entry: 'typeof fullMsg.data.historyId: ' + typeof fullMsg.data.historyId });
            logger.debug({ entry: 'fullMsg.data.historyId: ' + fullMsg.data.historyId });
            if (parseInt(fullMsg.data.historyId, 10) === eventDataObj.historyId) {
              logger.info({ entry: 'Found it! fullMsg = ' + JSON.stringify(fullMsg, null, 4) });
              return fullMsg.data;
            } else {
              return null;
            }
          });

        logger.debug({ entry: 'typeof msgOrNull: ' + typeof msgOrNull });
        logger.debug({ entry: 'msgOrNull: ' + JSON.stringify(msgOrNull, null, 4) });
        if (msgOrNull != null) {
          // We found it!
          logger.info({ entry: 'Still found it! returning ' + msgOrNull });
          return msgOrNull;
        }
      }

      logger.error({ entry: 'Returning null :(' });
      logger.warn({ entry: 'List was: ' + JSON.stringify(list, null, 4) });
      Promise.reject(new Error('Could not find message with historyId ' + eventDataObj.historyId));
    })
    .then((msg) => {
      logger.info({ entry: 'Message metadata:\n' + JSON.stringify(msg, null, 4) });
      // logger.info({ entry: 'URL for message: https://mail.google.com/mail?authuser=' + emailAddress + '#all/' + msg.id });
      // const notification = {

      // }

      // request(notification, function (notifError, notifResponse, notifBody) {
      //   if (notifError) logger.error({ entry: })
      // });
    })
    .catch((err) => {
      // Handle unexpected errors
      logger.error({ entry: 'Caught error: ' + err });
    });
};

/*
exports.onNewMessage = (event) => {
  const { Datastore } = require('@google-cloud/datastore');
  const datastore = new Datastore({ databaseId: 'gmail-notifier' });
  // const request = require('teeny-request').teenyRequest;

  logger.info({ entry: 'New event!' });
  logger.debug({ entry: 'Raw event:\n' + JSON.stringify(event, null, 4) });
  // Parse the Pub/Sub message
  const dataStr = Buffer.from(event.data, 'base64').toString('ascii');
  const dataObj = JSON.parse(dataStr);

  logger.debug({ entry: 'Decoded:\n' + JSON.stringify(dataObj, null, 4) });
  logger.debug({ entry: 'Decoded history ID:\n' + dataObj.historyId });

  const emailAddress = dataObj.emailAddress;
  oauth.fetchToken(emailAddress)
    .then(() => {
      return datastore.get(datastore.key(['lastHistoryId', emailAddress]))
      // .catch((e) => {
      //   // No such key yet if we got here, so we'll store one.
      //   // We'll miss this message, but that's ok.
      //   logger.error({ entry: 'Caught ' + e });
      //   datastore.save({
      //     key: datastore.key(['lastHistoryId', emailAddress]),
      //     data: dataObj.historyId
      //   })
      //     .then((datastoreResponse) => {
      //       logger.error({ entry: 'Saved in datastore after ' + e });
      //       logger.error({ entry: 'Datastore response was ' + datastoreResponse.toJSON() });
      //     })
      //     .catch((e2) => {
      //       logger.error({ entry: 'Caught an additional error: ' + e2 });
      //     });

      //   Promise.reject(e);
      // })
        .then((value) => {
          logger.info({ entry: 'typeof(value) :' + typeof value });
          logger.info({ entry: 'value of value: ' + value });
          logger.info({ entry: 'JSON of value: ' + JSON.stringify(value, null, 4) });
          if (value == null || value === '' ||
          (Object.prototype.hasOwnProperty.call(value, 'length') && value.length === 0) ||
          (Object.prototype.hasOwnProperty.call(value, 'length') && value.length === 1 && value[0] == null)) {
            // No such key yet if we got here, so we'll store one.
            // We'll miss this message, but that's ok.
            logger.error({ entry: 'Setting key: ' + ['lastHistoryId', emailAddress] });
            logger.error({ entry: 'Setting data: ' + JSON.stringify({ historyId: dataObj.historyId }) });
            datastore.save({
              key: datastore.key(['lastHistoryId', emailAddress]),
              data: { historyId: dataObj.historyId }
            })
              .then((datastoreResponse) => {
                logger.error({ entry: 'Saved in datastore after null/empty string value' });
                logger.error({ entry: 'Datastore response was ' + datastoreResponse });
              })
              .catch((e2) => {
                logger.error({ entry: 'Caught an error: ' + e2 });
              });
            return Promise.reject(new Error('value is empty!'));
          } else {
            logger.info({ entry: 'Successfully got value!' });
            return Promise.all([
              Promise.resolve(value[0].historyId),
              // Update history value
              datastore.save({
                key: datastore.key(['lastHistoryId', emailAddress]),
                data: { historyId: dataObj.historyId }
              })
            ]);
          }
        });
    })
    .then(([lastHistoryId, _]) => {
      logger.info({ entry: 'lastHistoryId:\n' + JSON.stringify(lastHistoryId, null, 4) });
      return gmail.users.history.list({
        userId: emailAddress,
        startHistoryId: lastHistoryId,
        historyTypes: ['messageAdded']
      });
    })
    .then((response) => {
      logger.info({ entry: 'response:\n' + JSON.stringify(response, null, 4) });
      logger.info({ entry: 'response.data.history:\n' + JSON.stringify(response.data.history, null, 4) });
      logger.info({ entry: 'response.data.history[response.data.history.length - 1]:\n' + JSON.stringify(response.data.history[response.data.history.length - 1], null, 4) });
      var history = response.data.history;
      gmail.users.messages.list({
        userId: emailAddress,
        q: 'in:anywhere'
      })
      return gmail.users.messages.get({
        userId: emailAddress,
        id: history.messagesAdded.message.id,
        format: 'metadata'
      });
    }) // Most recent message
    .then((msg) => {
      logger.info({ entry: 'Message metadata:\n' + JSON.stringify(msg, null, 4) });
      logger.info({ entry: 'URL for message: https://mail.google.com/mail?authuser=' + emailAddress + '#all/' + msg.id });
      // const notification = {

      // }

      // request(notification, function (notifError, notifResponse, notifBody) {
      //   if (notifError) logger.error({ entry: })
      // });
    })
    .catch((err) => {
      // Handle unexpected errors
      logger.error({ entry: 'Caught error: ' + err });
    });
};
*/
