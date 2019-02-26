import auth from 'feathers-authentication';
import jwt from 'feathers-authentication-jwt';
import local from 'feathers-authentication-local';
// import oauth1 from 'feathers-authentication-oauth1';
// import oauth2 from 'feathers-authentication-oauth2';
// import FacebookTokenStrategy from 'passport-facebook-token';
import { discard, iff } from 'feathers-hooks-common';
import { disallowNonAdmin, isAOR } from '../../hooks';

export { default as socketAuth } from './socketAuth';

const authenticate = auth.hooks.authenticate;

function populateUser(authConfig) {
  return hook => hook.app.passport.verifyJWT(hook.result.accessToken, authConfig)
    .then(payload => hook.app.service('users').get(payload.userId))
    .then(user => {
      user._orders = []
      hook.result.user = user;
    });
}

function restToSocketAuth() {
  return hook => {
    if (hook.params.provider !== 'rest') return hook;
    const { accessToken, user } = hook.result;
    const { socketId } = hook.data;
    if (socketId && hook.app.io && accessToken) {
      const userSocket = Object.values(hook.app.io.sockets.connected).find(socket => socket.client.id === socketId);
      if (userSocket) {
        Object.assign(userSocket.feathers, {
          accessToken,
          user,
          authenticated: true
        });
      }
    }
    return hook;
  };
}

export default function authenticationService() {
  const app = this;

  app.configure(auth(app.get('auth')))
    .configure(jwt())
    .configure(local())
    // .configure(oauth1()) // TODO twitter example
    // .configure(oauth2({
    //   name: 'facebook', // if the name differs from your config key you need to pass your config options explicitly
    //   Strategy: FacebookTokenStrategy
    // }))
    ;

  // delete the authentification delete route from the doc since it's 100% useless right now
  // they need to add blacklist support for this to be usefull
  delete app.docs.paths['/authentication/{id}'];

  app.docs.paths['/authentication'].post.description = `
    Use this api to request a JWT token for the user.
    You can then pass this token to the others api's to authentificate the request.
  `;

  app.docs.definitions = {
    authentication: {
      type: 'object',
      required: ['email', 'password'],
      properties: {
        email: {
          type: 'string',
          description: 'The user email.',
          example: 'user@exemple.com'
        },
        password: {
          type: 'string',
          description: 'The user password.',
          example: 'hunter2'
        },
        strategy: {
          type: 'string',
          description: 'The login strategy used.',
          enum: ['local', 'jwt'],
          example: 'local'
        }
      }
    }
  };

  app.service('authentication')
    .hooks({
      before: {
        create: [
          // You can chain multiple strategies on create method
          authenticate(['jwt', 'local'/* ,'facebook' */]),
          // this is not actually secure and is only there to cleanly block non admin from loging in AOR.
          // it could easily be omited from the request headers to bypass this check.
          // the actual security happen inside the services hooks file by blocking methods that should not be used without an admin role.
          iff(isAOR, disallowNonAdmin())
        ],
        remove: authenticate('jwt') // this is 100% useless right now until they add JWT token blacklist support or we implement it ourself.
      },
      after: {
        create: [
          populateUser(app.get('auth')),
          discard('user.password'),
          restToSocketAuth()
        ]
      }
    });
}
