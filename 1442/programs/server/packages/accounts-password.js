(function () {

/* Imports */
var Meteor = Package.meteor.Meteor;
var global = Package.meteor.global;
var meteorEnv = Package.meteor.meteorEnv;
var NpmModuleBcrypt = Package['npm-bcrypt'].NpmModuleBcrypt;
var Accounts = Package['accounts-base'].Accounts;
var SRP = Package.srp.SRP;
var SHA256 = Package.sha.SHA256;
var EJSON = Package.ejson.EJSON;
var DDP = Package['ddp-client'].DDP;
var DDPServer = Package['ddp-server'].DDPServer;
var Email = Package.email.Email;
var EmailInternals = Package.email.EmailInternals;
var Random = Package.random.Random;
var check = Package.check.check;
var Match = Package.check.Match;
var ECMAScript = Package.ecmascript.ECMAScript;
var meteorInstall = Package.modules.meteorInstall;
var Promise = Package.promise.Promise;

var require = meteorInstall({"node_modules":{"meteor":{"accounts-password":{"email_templates.js":function module(){

/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//                                                                                                                     //
// packages/accounts-password/email_templates.js                                                                       //
//                                                                                                                     //
/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
                                                                                                                       //
const greet = welcomeMsg => (user, url) => {
  const greeting = user.profile && user.profile.name ? "Hello ".concat(user.profile.name, ",") : "Hello,";
  return "".concat(greeting, "\n\n").concat(welcomeMsg, ", simply click the link below.\n\n").concat(url, "\n\nThanks.\n");
};
/**
 * @summary Options to customize emails sent from the Accounts system.
 * @locus Server
 * @importFromPackage accounts-base
 */


Accounts.emailTemplates = {
  from: "Accounts Example <no-reply@example.com>",
  siteName: Meteor.absoluteUrl().replace(/^https?:\/\//, '').replace(/\/$/, ''),
  resetPassword: {
    subject: () => "How to reset your password on ".concat(Accounts.emailTemplates.siteName),
    text: greet("To reset your password")
  },
  verifyEmail: {
    subject: () => "How to verify email address on ".concat(Accounts.emailTemplates.siteName),
    text: greet("To verify your account email")
  },
  enrollAccount: {
    subject: () => "An account has been created for you on ".concat(Accounts.emailTemplates.siteName),
    text: greet("To start using the service")
  }
};
/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

},"password_server.js":function module(require,exports,module){

/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//                                                                                                                     //
// packages/accounts-password/password_server.js                                                                       //
//                                                                                                                     //
/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
                                                                                                                       //
let _objectSpread;

module.link("@babel/runtime/helpers/objectSpread2", {
  default(v) {
    _objectSpread = v;
  }

}, 0);
/// BCRYPT
const bcrypt = NpmModuleBcrypt;
const bcryptHash = Meteor.wrapAsync(bcrypt.hash);
const bcryptCompare = Meteor.wrapAsync(bcrypt.compare); // Utility for grabbing user

const getUserById = (id, options) => Meteor.users.findOne(id, Accounts._addDefaultFieldSelector(options)); // User records have a 'services.password.bcrypt' field on them to hold
// their hashed passwords (unless they have a 'services.password.srp'
// field, in which case they will be upgraded to bcrypt the next time
// they log in).
//
// When the client sends a password to the server, it can either be a
// string (the plaintext password) or an object with keys 'digest' and
// 'algorithm' (must be "sha-256" for now). The Meteor client always sends
// password objects { digest: *, algorithm: "sha-256" }, but DDP clients
// that don't have access to SHA can just send plaintext passwords as
// strings.
//
// When the server receives a plaintext password as a string, it always
// hashes it with SHA256 before passing it into bcrypt. When the server
// receives a password as an object, it asserts that the algorithm is
// "sha-256" and then passes the digest to bcrypt.


Accounts._bcryptRounds = () => Accounts._options.bcryptRounds || 10; // Given a 'password' from the client, extract the string that we should
// bcrypt. 'password' can be one of:
//  - String (the plaintext password)
//  - Object with 'digest' and 'algorithm' keys. 'algorithm' must be "sha-256".
//


const getPasswordString = password => {
  if (typeof password === "string") {
    password = SHA256(password);
  } else {
    // 'password' is an object
    if (password.algorithm !== "sha-256") {
      throw new Error("Invalid password hash algorithm. " + "Only 'sha-256' is allowed.");
    }

    password = password.digest;
  }

  return password;
}; // Use bcrypt to hash the password for storage in the database.
// `password` can be a string (in which case it will be run through
// SHA256 before bcrypt) or an object with properties `digest` and
// `algorithm` (in which case we bcrypt `password.digest`).
//


const hashPassword = password => {
  password = getPasswordString(password);
  return bcryptHash(password, Accounts._bcryptRounds());
}; // Extract the number of rounds used in the specified bcrypt hash.


const getRoundsFromBcryptHash = hash => {
  let rounds;

  if (hash) {
    const hashSegments = hash.split('$');

    if (hashSegments.length > 2) {
      rounds = parseInt(hashSegments[2], 10);
    }
  }

  return rounds;
}; // Check whether the provided password matches the bcrypt'ed password in
// the database user record. `password` can be a string (in which case
// it will be run through SHA256 before bcrypt) or an object with
// properties `digest` and `algorithm` (in which case we bcrypt
// `password.digest`).
//
// The user parameter needs at least user._id and user.services


Accounts._checkPasswordUserFields = {
  _id: 1,
  services: 1
}, //
Accounts._checkPassword = (user, password) => {
  const result = {
    userId: user._id
  };
  const formattedPassword = getPasswordString(password);
  const hash = user.services.password.bcrypt;
  const hashRounds = getRoundsFromBcryptHash(hash);

  if (!bcryptCompare(formattedPassword, hash)) {
    result.error = handleError("Incorrect password", false);
  } else if (hash && Accounts._bcryptRounds() != hashRounds) {
    // The password checks out, but the user's bcrypt hash needs to be updated.
    Meteor.defer(() => {
      Meteor.users.update({
        _id: user._id
      }, {
        $set: {
          'services.password.bcrypt': bcryptHash(formattedPassword, Accounts._bcryptRounds())
        }
      });
    });
  }

  return result;
};
const checkPassword = Accounts._checkPassword; ///
/// ERROR HANDLER
///

const handleError = function (msg) {
  let throwError = arguments.length > 1 && arguments[1] !== undefined ? arguments[1] : true;
  const error = new Meteor.Error(403, Accounts._options.ambiguousErrorMessages ? "Something went wrong. Please check your credentials." : msg);

  if (throwError) {
    throw error;
  }

  return error;
}; ///
/// LOGIN
///


Accounts._findUserByQuery = (query, options) => {
  let user = null;

  if (query.id) {
    // default field selector is added within getUserById()
    user = getUserById(query.id, options);
  } else {
    options = Accounts._addDefaultFieldSelector(options);
    let fieldName;
    let fieldValue;

    if (query.username) {
      fieldName = 'username';
      fieldValue = query.username;
    } else if (query.email) {
      fieldName = 'emails.address';
      fieldValue = query.email;
    } else {
      throw new Error("shouldn't happen (validation missed something)");
    }

    let selector = {};
    selector[fieldName] = fieldValue;
    user = Meteor.users.findOne(selector, options); // If user is not found, try a case insensitive lookup

    if (!user) {
      selector = selectorForFastCaseInsensitiveLookup(fieldName, fieldValue);
      const candidateUsers = Meteor.users.find(selector, options).fetch(); // No match if multiple candidates are found

      if (candidateUsers.length === 1) {
        user = candidateUsers[0];
      }
    }
  }

  return user;
};
/**
 * @summary Finds the user with the specified username.
 * First tries to match username case sensitively; if that fails, it
 * tries case insensitively; but if more than one user matches the case
 * insensitive search, it returns null.
 * @locus Server
 * @param {String} username The username to look for
 * @param {Object} [options]
 * @param {MongoFieldSpecifier} options.fields Dictionary of fields to return or exclude.
 * @returns {Object} A user if found, else null
 * @importFromPackage accounts-base
 */


Accounts.findUserByUsername = (username, options) => Accounts._findUserByQuery({
  username
}, options);
/**
 * @summary Finds the user with the specified email.
 * First tries to match email case sensitively; if that fails, it
 * tries case insensitively; but if more than one user matches the case
 * insensitive search, it returns null.
 * @locus Server
 * @param {String} email The email address to look for
 * @param {Object} [options]
 * @param {MongoFieldSpecifier} options.fields Dictionary of fields to return or exclude.
 * @returns {Object} A user if found, else null
 * @importFromPackage accounts-base
 */


Accounts.findUserByEmail = (email, options) => Accounts._findUserByQuery({
  email
}, options); // Generates a MongoDB selector that can be used to perform a fast case
// insensitive lookup for the given fieldName and string. Since MongoDB does
// not support case insensitive indexes, and case insensitive regex queries
// are slow, we construct a set of prefix selectors for all permutations of
// the first 4 characters ourselves. We first attempt to matching against
// these, and because 'prefix expression' regex queries do use indexes (see
// http://docs.mongodb.org/v2.6/reference/operator/query/regex/#index-use),
// this has been found to greatly improve performance (from 1200ms to 5ms in a
// test with 1.000.000 users).


const selectorForFastCaseInsensitiveLookup = (fieldName, string) => {
  // Performance seems to improve up to 4 prefix characters
  const prefix = string.substring(0, Math.min(string.length, 4));
  const orClause = generateCasePermutationsForString(prefix).map(prefixPermutation => {
    const selector = {};
    selector[fieldName] = new RegExp("^".concat(Meteor._escapeRegExp(prefixPermutation)));
    return selector;
  });
  const caseInsensitiveClause = {};
  caseInsensitiveClause[fieldName] = new RegExp("^".concat(Meteor._escapeRegExp(string), "$"), 'i');
  return {
    $and: [{
      $or: orClause
    }, caseInsensitiveClause]
  };
}; // Generates permutations of all case variations of a given string.


const generateCasePermutationsForString = string => {
  let permutations = [''];

  for (let i = 0; i < string.length; i++) {
    const ch = string.charAt(i);
    permutations = [].concat(...permutations.map(prefix => {
      const lowerCaseChar = ch.toLowerCase();
      const upperCaseChar = ch.toUpperCase(); // Don't add unneccesary permutations when ch is not a letter

      if (lowerCaseChar === upperCaseChar) {
        return [prefix + ch];
      } else {
        return [prefix + lowerCaseChar, prefix + upperCaseChar];
      }
    }));
  }

  return permutations;
};

const checkForCaseInsensitiveDuplicates = (fieldName, displayName, fieldValue, ownUserId) => {
  // Some tests need the ability to add users with the same case insensitive
  // value, hence the _skipCaseInsensitiveChecksForTest check
  const skipCheck = Object.prototype.hasOwnProperty.call(Accounts._skipCaseInsensitiveChecksForTest, fieldValue);

  if (fieldValue && !skipCheck) {
    const matchedUsers = Meteor.users.find(selectorForFastCaseInsensitiveLookup(fieldName, fieldValue), {
      fields: {
        _id: 1
      },
      // we only need a maximum of 2 users for the logic below to work
      limit: 2
    }).fetch();

    if (matchedUsers.length > 0 && ( // If we don't have a userId yet, any match we find is a duplicate
    !ownUserId || // Otherwise, check to see if there are multiple matches or a match
    // that is not us
    matchedUsers.length > 1 || matchedUsers[0]._id !== ownUserId)) {
      handleError("".concat(displayName, " already exists."));
    }
  }
}; // XXX maybe this belongs in the check package


const NonEmptyString = Match.Where(x => {
  check(x, String);
  return x.length > 0;
});
const userQueryValidator = Match.Where(user => {
  check(user, {
    id: Match.Optional(NonEmptyString),
    username: Match.Optional(NonEmptyString),
    email: Match.Optional(NonEmptyString)
  });
  if (Object.keys(user).length !== 1) throw new Match.Error("User property must have exactly one field");
  return true;
});
const passwordValidator = Match.OneOf(String, {
  digest: String,
  algorithm: String
}); // Handler to login with a password.
//
// The Meteor client sets options.password to an object with keys
// 'digest' (set to SHA256(password)) and 'algorithm' ("sha-256").
//
// For other DDP clients which don't have access to SHA, the handler
// also accepts the plaintext password in options.password as a string.
//
// (It might be nice if servers could turn the plaintext password
// option off. Or maybe it should be opt-in, not opt-out?
// Accounts.config option?)
//
// Note that neither password option is secure without SSL.
//

Accounts.registerLoginHandler("password", options => {
  if (!options.password || options.srp) return undefined; // don't handle

  check(options, {
    user: userQueryValidator,
    password: passwordValidator
  });

  const user = Accounts._findUserByQuery(options.user, {
    fields: _objectSpread({
      services: 1
    }, Accounts._checkPasswordUserFields)
  });

  if (!user) {
    handleError("User not found");
  }

  if (!user.services || !user.services.password || !(user.services.password.bcrypt || user.services.password.srp)) {
    handleError("User has no password set");
  }

  if (!user.services.password.bcrypt) {
    if (typeof options.password === "string") {
      // The client has presented a plaintext password, and the user is
      // not upgraded to bcrypt yet. We don't attempt to tell the client
      // to upgrade to bcrypt, because it might be a standalone DDP
      // client doesn't know how to do such a thing.
      const verifier = user.services.password.srp;
      const newVerifier = SRP.generateVerifier(options.password, {
        identity: verifier.identity,
        salt: verifier.salt
      });

      if (verifier.verifier !== newVerifier.verifier) {
        return {
          userId: Accounts._options.ambiguousErrorMessages ? null : user._id,
          error: handleError("Incorrect password", false)
        };
      }

      return {
        userId: user._id
      };
    } else {
      // Tell the client to use the SRP upgrade process.
      throw new Meteor.Error(400, "old password format", EJSON.stringify({
        format: 'srp',
        identity: user.services.password.srp.identity
      }));
    }
  }

  return checkPassword(user, options.password);
}); // Handler to login using the SRP upgrade path. To use this login
// handler, the client must provide:
//   - srp: H(identity + ":" + password)
//   - password: a string or an object with properties 'digest' and 'algorithm'
//
// We use `options.srp` to verify that the client knows the correct
// password without doing a full SRP flow. Once we've checked that, we
// upgrade the user to bcrypt and remove the SRP information from the
// user document.
//
// The client ends up using this login handler after trying the normal
// login handler (above), which throws an error telling the client to
// try the SRP upgrade path.
//
// XXX COMPAT WITH 0.8.1.3

Accounts.registerLoginHandler("password", options => {
  if (!options.srp || !options.password) {
    return undefined; // don't handle
  }

  check(options, {
    user: userQueryValidator,
    srp: String,
    password: passwordValidator
  });

  const user = Accounts._findUserByQuery(options.user, {
    fields: _objectSpread({
      services: 1
    }, Accounts._checkPasswordUserFields)
  });

  if (!user) {
    handleError("User not found");
  } // Check to see if another simultaneous login has already upgraded
  // the user record to bcrypt.


  if (user.services && user.services.password && user.services.password.bcrypt) {
    return checkPassword(user, options.password);
  }

  if (!(user.services && user.services.password && user.services.password.srp)) {
    handleError("User has no password set");
  }

  const v1 = user.services.password.srp.verifier;
  const v2 = SRP.generateVerifier(null, {
    hashedIdentityAndPassword: options.srp,
    salt: user.services.password.srp.salt
  }).verifier;

  if (v1 !== v2) {
    return {
      userId: Accounts._options.ambiguousErrorMessages ? null : user._id,
      error: handleError("Incorrect password", false)
    };
  } // Upgrade to bcrypt on successful login.


  const salted = hashPassword(options.password);
  Meteor.users.update(user._id, {
    $unset: {
      'services.password.srp': 1
    },
    $set: {
      'services.password.bcrypt': salted
    }
  });
  return {
    userId: user._id
  };
}); ///
/// CHANGING
///

/**
 * @summary Change a user's username. Use this instead of updating the
 * database directly. The operation will fail if there is an existing user
 * with a username only differing in case.
 * @locus Server
 * @param {String} userId The ID of the user to update.
 * @param {String} newUsername A new username for the user.
 * @importFromPackage accounts-base
 */

Accounts.setUsername = (userId, newUsername) => {
  check(userId, NonEmptyString);
  check(newUsername, NonEmptyString);
  const user = getUserById(userId, {
    fields: {
      username: 1
    }
  });

  if (!user) {
    handleError("User not found");
  }

  const oldUsername = user.username; // Perform a case insensitive check for duplicates before update

  checkForCaseInsensitiveDuplicates('username', 'Username', newUsername, user._id);
  Meteor.users.update({
    _id: user._id
  }, {
    $set: {
      username: newUsername
    }
  }); // Perform another check after update, in case a matching user has been
  // inserted in the meantime

  try {
    checkForCaseInsensitiveDuplicates('username', 'Username', newUsername, user._id);
  } catch (ex) {
    // Undo update if the check fails
    Meteor.users.update({
      _id: user._id
    }, {
      $set: {
        username: oldUsername
      }
    });
    throw ex;
  }
}; // Let the user change their own password if they know the old
// password. `oldPassword` and `newPassword` should be objects with keys
// `digest` and `algorithm` (representing the SHA256 of the password).
//
// XXX COMPAT WITH 0.8.1.3
// Like the login method, if the user hasn't been upgraded from SRP to
// bcrypt yet, then this method will throw an 'old password format'
// error. The client should call the SRP upgrade login handler and then
// retry this method again.
//
// UNLIKE the login method, there is no way to avoid getting SRP upgrade
// errors thrown. The reasoning for this is that clients using this
// method directly will need to be updated anyway because we no longer
// support the SRP flow that they would have been doing to use this
// method previously.


Meteor.methods({
  changePassword: function (oldPassword, newPassword) {
    check(oldPassword, passwordValidator);
    check(newPassword, passwordValidator);

    if (!this.userId) {
      throw new Meteor.Error(401, "Must be logged in");
    }

    const user = getUserById(this.userId, {
      fields: _objectSpread({
        services: 1
      }, Accounts._checkPasswordUserFields)
    });

    if (!user) {
      handleError("User not found");
    }

    if (!user.services || !user.services.password || !user.services.password.bcrypt && !user.services.password.srp) {
      handleError("User has no password set");
    }

    if (!user.services.password.bcrypt) {
      throw new Meteor.Error(400, "old password format", EJSON.stringify({
        format: 'srp',
        identity: user.services.password.srp.identity
      }));
    }

    const result = checkPassword(user, oldPassword);

    if (result.error) {
      throw result.error;
    }

    const hashed = hashPassword(newPassword); // It would be better if this removed ALL existing tokens and replaced
    // the token for the current connection with a new one, but that would
    // be tricky, so we'll settle for just replacing all tokens other than
    // the one for the current connection.

    const currentToken = Accounts._getLoginToken(this.connection.id);

    Meteor.users.update({
      _id: this.userId
    }, {
      $set: {
        'services.password.bcrypt': hashed
      },
      $pull: {
        'services.resume.loginTokens': {
          hashedToken: {
            $ne: currentToken
          }
        }
      },
      $unset: {
        'services.password.reset': 1
      }
    });
    return {
      passwordChanged: true
    };
  }
}); // Force change the users password.

/**
 * @summary Forcibly change the password for a user.
 * @locus Server
 * @param {String} userId The id of the user to update.
 * @param {String} newPassword A new password for the user.
 * @param {Object} [options]
 * @param {Object} options.logout Logout all current connections with this userId (default: true)
 * @importFromPackage accounts-base
 */

Accounts.setPassword = (userId, newPlaintextPassword, options) => {
  options = _objectSpread({
    logout: true
  }, options);
  const user = getUserById(userId, {
    fields: {
      _id: 1
    }
  });

  if (!user) {
    throw new Meteor.Error(403, "User not found");
  }

  const update = {
    $unset: {
      'services.password.srp': 1,
      // XXX COMPAT WITH 0.8.1.3
      'services.password.reset': 1
    },
    $set: {
      'services.password.bcrypt': hashPassword(newPlaintextPassword)
    }
  };

  if (options.logout) {
    update.$unset['services.resume.loginTokens'] = 1;
  }

  Meteor.users.update({
    _id: user._id
  }, update);
}; ///
/// RESETTING VIA EMAIL
///
// Utility for plucking addresses from emails


const pluckAddresses = function () {
  let emails = arguments.length > 0 && arguments[0] !== undefined ? arguments[0] : [];
  return emails.map(email => email.address);
}; // Method called by a user to request a password reset email. This is
// the start of the reset process.


Meteor.methods({
  forgotPassword: options => {
    check(options, {
      email: String
    });
    const user = Accounts.findUserByEmail(options.email, {
      fields: {
        emails: 1
      }
    });

    if (!user) {
      handleError("User not found");
    }

    const emails = pluckAddresses(user.emails);
    const caseSensitiveEmail = emails.find(email => email.toLowerCase() === options.email.toLowerCase());
    Accounts.sendResetPasswordEmail(user._id, caseSensitiveEmail);
  }
});
/**
 * @summary Generates a reset token and saves it into the database.
 * @locus Server
 * @param {String} userId The id of the user to generate the reset token for.
 * @param {String} email Which address of the user to generate the reset token for. This address must be in the user's `emails` list. If `null`, defaults to the first email in the list.
 * @param {String} reason `resetPassword` or `enrollAccount`.
 * @param {Object} [extraTokenData] Optional additional data to be added into the token record.
 * @returns {Object} Object with {email, user, token} values.
 * @importFromPackage accounts-base
 */

Accounts.generateResetToken = (userId, email, reason, extraTokenData) => {
  // Make sure the user exists, and email is one of their addresses.
  // Don't limit the fields in the user object since the user is returned
  // by the function and some other fields might be used elsewhere.
  const user = getUserById(userId);

  if (!user) {
    handleError("Can't find user");
  } // pick the first email if we weren't passed an email.


  if (!email && user.emails && user.emails[0]) {
    email = user.emails[0].address;
  } // make sure we have a valid email


  if (!email || !pluckAddresses(user.emails).includes(email)) {
    handleError("No such email for user.");
  }

  const token = Random.secret();
  const tokenRecord = {
    token,
    email,
    when: new Date()
  };

  if (reason === 'resetPassword') {
    tokenRecord.reason = 'reset';
  } else if (reason === 'enrollAccount') {
    tokenRecord.reason = 'enroll';
  } else if (reason) {
    // fallback so that this function can be used for unknown reasons as well
    tokenRecord.reason = reason;
  }

  if (extraTokenData) {
    Object.assign(tokenRecord, extraTokenData);
  }

  Meteor.users.update({
    _id: user._id
  }, {
    $set: {
      'services.password.reset': tokenRecord
    }
  }); // before passing to template, update user object with new token

  Meteor._ensure(user, 'services', 'password').reset = tokenRecord;
  return {
    email,
    user,
    token
  };
};
/**
 * @summary Generates an e-mail verification token and saves it into the database.
 * @locus Server
 * @param {String} userId The id of the user to generate the  e-mail verification token for.
 * @param {String} email Which address of the user to generate the e-mail verification token for. This address must be in the user's `emails` list. If `null`, defaults to the first unverified email in the list.
 * @param {Object} [extraTokenData] Optional additional data to be added into the token record.
 * @returns {Object} Object with {email, user, token} values.
 * @importFromPackage accounts-base
 */


Accounts.generateVerificationToken = (userId, email, extraTokenData) => {
  // Make sure the user exists, and email is one of their addresses.
  // Don't limit the fields in the user object since the user is returned
  // by the function and some other fields might be used elsewhere.
  const user = getUserById(userId);

  if (!user) {
    handleError("Can't find user");
  } // pick the first unverified email if we weren't passed an email.


  if (!email) {
    const emailRecord = (user.emails || []).find(e => !e.verified);
    email = (emailRecord || {}).address;

    if (!email) {
      handleError("That user has no unverified email addresses.");
    }
  } // make sure we have a valid email


  if (!email || !pluckAddresses(user.emails).includes(email)) {
    handleError("No such email for user.");
  }

  const token = Random.secret();
  const tokenRecord = {
    token,
    // TODO: This should probably be renamed to "email" to match reset token record.
    address: email,
    when: new Date()
  };

  if (extraTokenData) {
    Object.assign(tokenRecord, extraTokenData);
  }

  Meteor.users.update({
    _id: user._id
  }, {
    $push: {
      'services.email.verificationTokens': tokenRecord
    }
  }); // before passing to template, update user object with new token

  Meteor._ensure(user, 'services', 'email');

  if (!user.services.email.verificationTokens) {
    user.services.email.verificationTokens = [];
  }

  user.services.email.verificationTokens.push(tokenRecord);
  return {
    email,
    user,
    token
  };
};
/**
 * @summary Creates options for email sending for reset password and enroll account emails.
 * You can use this function when customizing a reset password or enroll account email sending.
 * @locus Server
 * @param {Object} email Which address of the user's to send the email to.
 * @param {Object} user The user object to generate options for.
 * @param {String} url URL to which user is directed to confirm the email.
 * @param {String} reason `resetPassword` or `enrollAccount`.
 * @returns {Object} Options which can be passed to `Email.send`.
 * @importFromPackage accounts-base
 */


Accounts.generateOptionsForEmail = (email, user, url, reason) => {
  const options = {
    to: email,
    from: Accounts.emailTemplates[reason].from ? Accounts.emailTemplates[reason].from(user) : Accounts.emailTemplates.from,
    subject: Accounts.emailTemplates[reason].subject(user)
  };

  if (typeof Accounts.emailTemplates[reason].text === 'function') {
    options.text = Accounts.emailTemplates[reason].text(user, url);
  }

  if (typeof Accounts.emailTemplates[reason].html === 'function') {
    options.html = Accounts.emailTemplates[reason].html(user, url);
  }

  if (typeof Accounts.emailTemplates.headers === 'object') {
    options.headers = Accounts.emailTemplates.headers;
  }

  return options;
}; // send the user an email with a link that when opened allows the user
// to set a new password, without the old password.

/**
 * @summary Send an email with a link the user can use to reset their password.
 * @locus Server
 * @param {String} userId The id of the user to send email to.
 * @param {String} [email] Optional. Which address of the user's to send the email to. This address must be in the user's `emails` list. Defaults to the first email in the list.
 * @param {Object} [extraTokenData] Optional additional data to be added into the token record.
 * @returns {Object} Object with {email, user, token, url, options} values.
 * @importFromPackage accounts-base
 */


Accounts.sendResetPasswordEmail = (userId, email, extraTokenData) => {
  const {
    email: realEmail,
    user,
    token
  } = Accounts.generateResetToken(userId, email, 'resetPassword', extraTokenData);
  const url = Accounts.urls.resetPassword(token);
  const options = Accounts.generateOptionsForEmail(realEmail, user, url, 'resetPassword');
  Email.send(options);

  if (Meteor.isDevelopment) {
    console.log("\nReset password URL: ".concat(url));
  }

  return {
    email: realEmail,
    user,
    token,
    url,
    options
  };
}; // send the user an email informing them that their account was created, with
// a link that when opened both marks their email as verified and forces them
// to choose their password. The email must be one of the addresses in the
// user's emails field, or undefined to pick the first email automatically.
//
// This is not called automatically. It must be called manually if you
// want to use enrollment emails.

/**
 * @summary Send an email with a link the user can use to set their initial password.
 * @locus Server
 * @param {String} userId The id of the user to send email to.
 * @param {String} [email] Optional. Which address of the user's to send the email to. This address must be in the user's `emails` list. Defaults to the first email in the list.
 * @param {Object} [extraTokenData] Optional additional data to be added into the token record.
 * @returns {Object} Object with {email, user, token, url, options} values.
 * @importFromPackage accounts-base
 */


Accounts.sendEnrollmentEmail = (userId, email, extraTokenData) => {
  const {
    email: realEmail,
    user,
    token
  } = Accounts.generateResetToken(userId, email, 'enrollAccount', extraTokenData);
  const url = Accounts.urls.enrollAccount(token);
  const options = Accounts.generateOptionsForEmail(realEmail, user, url, 'enrollAccount');
  Email.send(options);

  if (Meteor.isDevelopment) {
    console.log("\nEnrollment email URL: ".concat(url));
  }

  return {
    email: realEmail,
    user,
    token,
    url,
    options
  };
}; // Take token from sendResetPasswordEmail or sendEnrollmentEmail, change
// the users password, and log them in.


Meteor.methods({
  resetPassword: function () {
    for (var _len = arguments.length, args = new Array(_len), _key = 0; _key < _len; _key++) {
      args[_key] = arguments[_key];
    }

    const token = args[0];
    const newPassword = args[1];
    return Accounts._loginMethod(this, "resetPassword", args, "password", () => {
      check(token, String);
      check(newPassword, passwordValidator);
      const user = Meteor.users.findOne({
        "services.password.reset.token": token
      }, {
        fields: {
          services: 1,
          emails: 1
        }
      });

      if (!user) {
        throw new Meteor.Error(403, "Token expired");
      }

      const {
        when,
        reason,
        email
      } = user.services.password.reset;

      let tokenLifetimeMs = Accounts._getPasswordResetTokenLifetimeMs();

      if (reason === "enroll") {
        tokenLifetimeMs = Accounts._getPasswordEnrollTokenLifetimeMs();
      }

      const currentTimeMs = Date.now();
      if (currentTimeMs - when > tokenLifetimeMs) throw new Meteor.Error(403, "Token expired");
      if (!pluckAddresses(user.emails).includes(email)) return {
        userId: user._id,
        error: new Meteor.Error(403, "Token has invalid email address")
      };
      const hashed = hashPassword(newPassword); // NOTE: We're about to invalidate tokens on the user, who we might be
      // logged in as. Make sure to avoid logging ourselves out if this
      // happens. But also make sure not to leave the connection in a state
      // of having a bad token set if things fail.

      const oldToken = Accounts._getLoginToken(this.connection.id);

      Accounts._setLoginToken(user._id, this.connection, null);

      const resetToOldToken = () => Accounts._setLoginToken(user._id, this.connection, oldToken);

      try {
        // Update the user record by:
        // - Changing the password to the new one
        // - Forgetting about the reset token that was just used
        // - Verifying their email, since they got the password reset via email.
        const affectedRecords = Meteor.users.update({
          _id: user._id,
          'emails.address': email,
          'services.password.reset.token': token
        }, {
          $set: {
            'services.password.bcrypt': hashed,
            'emails.$.verified': true
          },
          $unset: {
            'services.password.reset': 1,
            'services.password.srp': 1
          }
        });
        if (affectedRecords !== 1) return {
          userId: user._id,
          error: new Meteor.Error(403, "Invalid email")
        };
      } catch (err) {
        resetToOldToken();
        throw err;
      } // Replace all valid login tokens with new ones (changing
      // password should invalidate existing sessions).


      Accounts._clearAllLoginTokens(user._id);

      return {
        userId: user._id
      };
    });
  }
}); ///
/// EMAIL VERIFICATION
///
// send the user an email with a link that when opened marks that
// address as verified

/**
 * @summary Send an email with a link the user can use verify their email address.
 * @locus Server
 * @param {String} userId The id of the user to send email to.
 * @param {String} [email] Optional. Which address of the user's to send the email to. This address must be in the user's `emails` list. Defaults to the first unverified email in the list.
 * @param {Object} [extraTokenData] Optional additional data to be added into the token record.
 * @returns {Object} Object with {email, user, token, url, options} values.
 * @importFromPackage accounts-base
 */

Accounts.sendVerificationEmail = (userId, email, extraTokenData) => {
  // XXX Also generate a link using which someone can delete this
  // account if they own said address but weren't those who created
  // this account.
  const {
    email: realEmail,
    user,
    token
  } = Accounts.generateVerificationToken(userId, email, extraTokenData);
  const url = Accounts.urls.verifyEmail(token);
  const options = Accounts.generateOptionsForEmail(realEmail, user, url, 'verifyEmail');
  Email.send(options);

  if (Meteor.isDevelopment) {
    console.log("\nVerification email URL: ".concat(url));
  }

  return {
    email: realEmail,
    user,
    token,
    url,
    options
  };
}; // Take token from sendVerificationEmail, mark the email as verified,
// and log them in.


Meteor.methods({
  verifyEmail: function () {
    for (var _len2 = arguments.length, args = new Array(_len2), _key2 = 0; _key2 < _len2; _key2++) {
      args[_key2] = arguments[_key2];
    }

    const token = args[0];
    return Accounts._loginMethod(this, "verifyEmail", args, "password", () => {
      check(token, String);
      const user = Meteor.users.findOne({
        'services.email.verificationTokens.token': token
      }, {
        fields: {
          services: 1,
          emails: 1
        }
      });
      if (!user) throw new Meteor.Error(403, "Verify email link expired");
      const tokenRecord = user.services.email.verificationTokens.find(t => t.token == token);
      if (!tokenRecord) return {
        userId: user._id,
        error: new Meteor.Error(403, "Verify email link expired")
      };
      const emailsRecord = user.emails.find(e => e.address == tokenRecord.address);
      if (!emailsRecord) return {
        userId: user._id,
        error: new Meteor.Error(403, "Verify email link is for unknown address")
      }; // By including the address in the query, we can use 'emails.$' in the
      // modifier to get a reference to the specific object in the emails
      // array. See
      // http://www.mongodb.org/display/DOCS/Updating/#Updating-The%24positionaloperator)
      // http://www.mongodb.org/display/DOCS/Updating#Updating-%24pull

      Meteor.users.update({
        _id: user._id,
        'emails.address': tokenRecord.address
      }, {
        $set: {
          'emails.$.verified': true
        },
        $pull: {
          'services.email.verificationTokens': {
            address: tokenRecord.address
          }
        }
      });
      return {
        userId: user._id
      };
    });
  }
});
/**
 * @summary Add an email address for a user. Use this instead of directly
 * updating the database. The operation will fail if there is a different user
 * with an email only differing in case. If the specified user has an existing
 * email only differing in case however, we replace it.
 * @locus Server
 * @param {String} userId The ID of the user to update.
 * @param {String} newEmail A new email address for the user.
 * @param {Boolean} [verified] Optional - whether the new email address should
 * be marked as verified. Defaults to false.
 * @importFromPackage accounts-base
 */

Accounts.addEmail = (userId, newEmail, verified) => {
  check(userId, NonEmptyString);
  check(newEmail, NonEmptyString);
  check(verified, Match.Optional(Boolean));

  if (verified === void 0) {
    verified = false;
  }

  const user = getUserById(userId, {
    fields: {
      emails: 1
    }
  });
  if (!user) throw new Meteor.Error(403, "User not found"); // Allow users to change their own email to a version with a different case
  // We don't have to call checkForCaseInsensitiveDuplicates to do a case
  // insensitive check across all emails in the database here because: (1) if
  // there is no case-insensitive duplicate between this user and other users,
  // then we are OK and (2) if this would create a conflict with other users
  // then there would already be a case-insensitive duplicate and we can't fix
  // that in this code anyway.

  const caseInsensitiveRegExp = new RegExp("^".concat(Meteor._escapeRegExp(newEmail), "$"), 'i');
  const didUpdateOwnEmail = (user.emails || []).reduce((prev, email) => {
    if (caseInsensitiveRegExp.test(email.address)) {
      Meteor.users.update({
        _id: user._id,
        'emails.address': email.address
      }, {
        $set: {
          'emails.$.address': newEmail,
          'emails.$.verified': verified
        }
      });
      return true;
    } else {
      return prev;
    }
  }, false); // In the other updates below, we have to do another call to
  // checkForCaseInsensitiveDuplicates to make sure that no conflicting values
  // were added to the database in the meantime. We don't have to do this for
  // the case where the user is updating their email address to one that is the
  // same as before, but only different because of capitalization. Read the
  // big comment above to understand why.

  if (didUpdateOwnEmail) {
    return;
  } // Perform a case insensitive check for duplicates before update


  checkForCaseInsensitiveDuplicates('emails.address', 'Email', newEmail, user._id);
  Meteor.users.update({
    _id: user._id
  }, {
    $addToSet: {
      emails: {
        address: newEmail,
        verified: verified
      }
    }
  }); // Perform another check after update, in case a matching user has been
  // inserted in the meantime

  try {
    checkForCaseInsensitiveDuplicates('emails.address', 'Email', newEmail, user._id);
  } catch (ex) {
    // Undo update if the check fails
    Meteor.users.update({
      _id: user._id
    }, {
      $pull: {
        emails: {
          address: newEmail
        }
      }
    });
    throw ex;
  }
};
/**
 * @summary Remove an email address for a user. Use this instead of updating
 * the database directly.
 * @locus Server
 * @param {String} userId The ID of the user to update.
 * @param {String} email The email address to remove.
 * @importFromPackage accounts-base
 */


Accounts.removeEmail = (userId, email) => {
  check(userId, NonEmptyString);
  check(email, NonEmptyString);
  const user = getUserById(userId, {
    fields: {
      _id: 1
    }
  });
  if (!user) throw new Meteor.Error(403, "User not found");
  Meteor.users.update({
    _id: user._id
  }, {
    $pull: {
      emails: {
        address: email
      }
    }
  });
}; ///
/// CREATING USERS
///
// Shared createUser function called from the createUser method, both
// if originates in client or server code. Calls user provided hooks,
// does the actual user insertion.
//
// returns the user id


const createUser = options => {
  // Unknown keys allowed, because a onCreateUserHook can take arbitrary
  // options.
  check(options, Match.ObjectIncluding({
    username: Match.Optional(String),
    email: Match.Optional(String),
    password: Match.Optional(passwordValidator)
  }));
  const {
    username,
    email,
    password
  } = options;
  if (!username && !email) throw new Meteor.Error(400, "Need to set a username or email");
  const user = {
    services: {}
  };

  if (password) {
    const hashed = hashPassword(password);
    user.services.password = {
      bcrypt: hashed
    };
  }

  if (username) user.username = username;
  if (email) user.emails = [{
    address: email,
    verified: false
  }]; // Perform a case insensitive check before insert

  checkForCaseInsensitiveDuplicates('username', 'Username', username);
  checkForCaseInsensitiveDuplicates('emails.address', 'Email', email);
  const userId = Accounts.insertUserDoc(options, user); // Perform another check after insert, in case a matching user has been
  // inserted in the meantime

  try {
    checkForCaseInsensitiveDuplicates('username', 'Username', username, userId);
    checkForCaseInsensitiveDuplicates('emails.address', 'Email', email, userId);
  } catch (ex) {
    // Remove inserted user if the check fails
    Meteor.users.remove(userId);
    throw ex;
  }

  return userId;
}; // method for create user. Requests come from the client.


Meteor.methods({
  createUser: function () {
    for (var _len3 = arguments.length, args = new Array(_len3), _key3 = 0; _key3 < _len3; _key3++) {
      args[_key3] = arguments[_key3];
    }

    const options = args[0];
    return Accounts._loginMethod(this, "createUser", args, "password", () => {
      // createUser() above does more checking.
      check(options, Object);
      if (Accounts._options.forbidClientAccountCreation) return {
        error: new Meteor.Error(403, "Signups forbidden")
      }; // Create user. result contains id and token.

      const userId = createUser(options); // safety belt. createUser is supposed to throw on error. send 500 error
      // instead of sending a verification email with empty userid.

      if (!userId) throw new Error("createUser failed to insert new user"); // If `Accounts._options.sendVerificationEmail` is set, register
      // a token to verify the user's primary email, and send it to
      // that address.

      if (options.email && Accounts._options.sendVerificationEmail) Accounts.sendVerificationEmail(userId, options.email); // client gets logged in as the new user afterwards.

      return {
        userId: userId
      };
    });
  }
}); // Create user directly on the server.
//
// Unlike the client version, this does not log you in as this user
// after creation.
//
// returns userId or throws an error if it can't create
//
// XXX add another argument ("server options") that gets sent to onCreateUser,
// which is always empty when called from the createUser method? eg, "admin:
// true", which we want to prevent the client from setting, but which a custom
// method calling Accounts.createUser could set?
//

Accounts.createUser = (options, callback) => {
  options = _objectSpread({}, options); // XXX allow an optional callback?

  if (callback) {
    throw new Error("Accounts.createUser with callback not supported on the server yet.");
  }

  return createUser(options);
}; ///
/// PASSWORD-SPECIFIC INDEXES ON USERS
///


Meteor.users._ensureIndex('services.email.verificationTokens.token', {
  unique: true,
  sparse: true
});

Meteor.users._ensureIndex('services.password.reset.token', {
  unique: true,
  sparse: true
});
/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

}}}}},{
  "extensions": [
    ".js",
    ".json"
  ]
});

require("/node_modules/meteor/accounts-password/email_templates.js");
require("/node_modules/meteor/accounts-password/password_server.js");

/* Exports */
Package._define("accounts-password");

})();

//# sourceURL=meteor://💻app/packages/accounts-password.js
//# sourceMappingURL=data:application/json;charset=utf8;base64,eyJ2ZXJzaW9uIjozLCJzb3VyY2VzIjpbIm1ldGVvcjovL/CfkrthcHAvcGFja2FnZXMvYWNjb3VudHMtcGFzc3dvcmQvZW1haWxfdGVtcGxhdGVzLmpzIiwibWV0ZW9yOi8v8J+Su2FwcC9wYWNrYWdlcy9hY2NvdW50cy1wYXNzd29yZC9wYXNzd29yZF9zZXJ2ZXIuanMiXSwibmFtZXMiOlsiZ3JlZXQiLCJ3ZWxjb21lTXNnIiwidXNlciIsInVybCIsImdyZWV0aW5nIiwicHJvZmlsZSIsIm5hbWUiLCJBY2NvdW50cyIsImVtYWlsVGVtcGxhdGVzIiwiZnJvbSIsInNpdGVOYW1lIiwiTWV0ZW9yIiwiYWJzb2x1dGVVcmwiLCJyZXBsYWNlIiwicmVzZXRQYXNzd29yZCIsInN1YmplY3QiLCJ0ZXh0IiwidmVyaWZ5RW1haWwiLCJlbnJvbGxBY2NvdW50IiwiX29iamVjdFNwcmVhZCIsIm1vZHVsZSIsImxpbmsiLCJkZWZhdWx0IiwidiIsImJjcnlwdCIsIk5wbU1vZHVsZUJjcnlwdCIsImJjcnlwdEhhc2giLCJ3cmFwQXN5bmMiLCJoYXNoIiwiYmNyeXB0Q29tcGFyZSIsImNvbXBhcmUiLCJnZXRVc2VyQnlJZCIsImlkIiwib3B0aW9ucyIsInVzZXJzIiwiZmluZE9uZSIsIl9hZGREZWZhdWx0RmllbGRTZWxlY3RvciIsIl9iY3J5cHRSb3VuZHMiLCJfb3B0aW9ucyIsImJjcnlwdFJvdW5kcyIsImdldFBhc3N3b3JkU3RyaW5nIiwicGFzc3dvcmQiLCJTSEEyNTYiLCJhbGdvcml0aG0iLCJFcnJvciIsImRpZ2VzdCIsImhhc2hQYXNzd29yZCIsImdldFJvdW5kc0Zyb21CY3J5cHRIYXNoIiwicm91bmRzIiwiaGFzaFNlZ21lbnRzIiwic3BsaXQiLCJsZW5ndGgiLCJwYXJzZUludCIsIl9jaGVja1Bhc3N3b3JkVXNlckZpZWxkcyIsIl9pZCIsInNlcnZpY2VzIiwiX2NoZWNrUGFzc3dvcmQiLCJyZXN1bHQiLCJ1c2VySWQiLCJmb3JtYXR0ZWRQYXNzd29yZCIsImhhc2hSb3VuZHMiLCJlcnJvciIsImhhbmRsZUVycm9yIiwiZGVmZXIiLCJ1cGRhdGUiLCIkc2V0IiwiY2hlY2tQYXNzd29yZCIsIm1zZyIsInRocm93RXJyb3IiLCJhbWJpZ3VvdXNFcnJvck1lc3NhZ2VzIiwiX2ZpbmRVc2VyQnlRdWVyeSIsInF1ZXJ5IiwiZmllbGROYW1lIiwiZmllbGRWYWx1ZSIsInVzZXJuYW1lIiwiZW1haWwiLCJzZWxlY3RvciIsInNlbGVjdG9yRm9yRmFzdENhc2VJbnNlbnNpdGl2ZUxvb2t1cCIsImNhbmRpZGF0ZVVzZXJzIiwiZmluZCIsImZldGNoIiwiZmluZFVzZXJCeVVzZXJuYW1lIiwiZmluZFVzZXJCeUVtYWlsIiwic3RyaW5nIiwicHJlZml4Iiwic3Vic3RyaW5nIiwiTWF0aCIsIm1pbiIsIm9yQ2xhdXNlIiwiZ2VuZXJhdGVDYXNlUGVybXV0YXRpb25zRm9yU3RyaW5nIiwibWFwIiwicHJlZml4UGVybXV0YXRpb24iLCJSZWdFeHAiLCJfZXNjYXBlUmVnRXhwIiwiY2FzZUluc2Vuc2l0aXZlQ2xhdXNlIiwiJGFuZCIsIiRvciIsInBlcm11dGF0aW9ucyIsImkiLCJjaCIsImNoYXJBdCIsImNvbmNhdCIsImxvd2VyQ2FzZUNoYXIiLCJ0b0xvd2VyQ2FzZSIsInVwcGVyQ2FzZUNoYXIiLCJ0b1VwcGVyQ2FzZSIsImNoZWNrRm9yQ2FzZUluc2Vuc2l0aXZlRHVwbGljYXRlcyIsImRpc3BsYXlOYW1lIiwib3duVXNlcklkIiwic2tpcENoZWNrIiwiT2JqZWN0IiwicHJvdG90eXBlIiwiaGFzT3duUHJvcGVydHkiLCJjYWxsIiwiX3NraXBDYXNlSW5zZW5zaXRpdmVDaGVja3NGb3JUZXN0IiwibWF0Y2hlZFVzZXJzIiwiZmllbGRzIiwibGltaXQiLCJOb25FbXB0eVN0cmluZyIsIk1hdGNoIiwiV2hlcmUiLCJ4IiwiY2hlY2siLCJTdHJpbmciLCJ1c2VyUXVlcnlWYWxpZGF0b3IiLCJPcHRpb25hbCIsImtleXMiLCJwYXNzd29yZFZhbGlkYXRvciIsIk9uZU9mIiwicmVnaXN0ZXJMb2dpbkhhbmRsZXIiLCJzcnAiLCJ1bmRlZmluZWQiLCJ2ZXJpZmllciIsIm5ld1ZlcmlmaWVyIiwiU1JQIiwiZ2VuZXJhdGVWZXJpZmllciIsImlkZW50aXR5Iiwic2FsdCIsIkVKU09OIiwic3RyaW5naWZ5IiwiZm9ybWF0IiwidjEiLCJ2MiIsImhhc2hlZElkZW50aXR5QW5kUGFzc3dvcmQiLCJzYWx0ZWQiLCIkdW5zZXQiLCJzZXRVc2VybmFtZSIsIm5ld1VzZXJuYW1lIiwib2xkVXNlcm5hbWUiLCJleCIsIm1ldGhvZHMiLCJjaGFuZ2VQYXNzd29yZCIsIm9sZFBhc3N3b3JkIiwibmV3UGFzc3dvcmQiLCJoYXNoZWQiLCJjdXJyZW50VG9rZW4iLCJfZ2V0TG9naW5Ub2tlbiIsImNvbm5lY3Rpb24iLCIkcHVsbCIsImhhc2hlZFRva2VuIiwiJG5lIiwicGFzc3dvcmRDaGFuZ2VkIiwic2V0UGFzc3dvcmQiLCJuZXdQbGFpbnRleHRQYXNzd29yZCIsImxvZ291dCIsInBsdWNrQWRkcmVzc2VzIiwiZW1haWxzIiwiYWRkcmVzcyIsImZvcmdvdFBhc3N3b3JkIiwiY2FzZVNlbnNpdGl2ZUVtYWlsIiwic2VuZFJlc2V0UGFzc3dvcmRFbWFpbCIsImdlbmVyYXRlUmVzZXRUb2tlbiIsInJlYXNvbiIsImV4dHJhVG9rZW5EYXRhIiwiaW5jbHVkZXMiLCJ0b2tlbiIsIlJhbmRvbSIsInNlY3JldCIsInRva2VuUmVjb3JkIiwid2hlbiIsIkRhdGUiLCJhc3NpZ24iLCJfZW5zdXJlIiwicmVzZXQiLCJnZW5lcmF0ZVZlcmlmaWNhdGlvblRva2VuIiwiZW1haWxSZWNvcmQiLCJlIiwidmVyaWZpZWQiLCIkcHVzaCIsInZlcmlmaWNhdGlvblRva2VucyIsInB1c2giLCJnZW5lcmF0ZU9wdGlvbnNGb3JFbWFpbCIsInRvIiwiaHRtbCIsImhlYWRlcnMiLCJyZWFsRW1haWwiLCJ1cmxzIiwiRW1haWwiLCJzZW5kIiwiaXNEZXZlbG9wbWVudCIsImNvbnNvbGUiLCJsb2ciLCJzZW5kRW5yb2xsbWVudEVtYWlsIiwiYXJncyIsIl9sb2dpbk1ldGhvZCIsInRva2VuTGlmZXRpbWVNcyIsIl9nZXRQYXNzd29yZFJlc2V0VG9rZW5MaWZldGltZU1zIiwiX2dldFBhc3N3b3JkRW5yb2xsVG9rZW5MaWZldGltZU1zIiwiY3VycmVudFRpbWVNcyIsIm5vdyIsIm9sZFRva2VuIiwiX3NldExvZ2luVG9rZW4iLCJyZXNldFRvT2xkVG9rZW4iLCJhZmZlY3RlZFJlY29yZHMiLCJlcnIiLCJfY2xlYXJBbGxMb2dpblRva2VucyIsInNlbmRWZXJpZmljYXRpb25FbWFpbCIsInQiLCJlbWFpbHNSZWNvcmQiLCJhZGRFbWFpbCIsIm5ld0VtYWlsIiwiQm9vbGVhbiIsImNhc2VJbnNlbnNpdGl2ZVJlZ0V4cCIsImRpZFVwZGF0ZU93bkVtYWlsIiwicmVkdWNlIiwicHJldiIsInRlc3QiLCIkYWRkVG9TZXQiLCJyZW1vdmVFbWFpbCIsImNyZWF0ZVVzZXIiLCJPYmplY3RJbmNsdWRpbmciLCJpbnNlcnRVc2VyRG9jIiwicmVtb3ZlIiwiZm9yYmlkQ2xpZW50QWNjb3VudENyZWF0aW9uIiwiY2FsbGJhY2siLCJfZW5zdXJlSW5kZXgiLCJ1bmlxdWUiLCJzcGFyc2UiXSwibWFwcGluZ3MiOiI7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7OztBQUFBLE1BQU1BLEtBQUssR0FBR0MsVUFBVSxJQUFJLENBQUNDLElBQUQsRUFBT0MsR0FBUCxLQUFlO0FBQ3JDLFFBQU1DLFFBQVEsR0FBSUYsSUFBSSxDQUFDRyxPQUFMLElBQWdCSCxJQUFJLENBQUNHLE9BQUwsQ0FBYUMsSUFBOUIsbUJBQ0RKLElBQUksQ0FBQ0csT0FBTCxDQUFhQyxJQURaLFNBQ3VCLFFBRHhDO0FBRUEsbUJBQVVGLFFBQVYsaUJBRUpILFVBRkksK0NBSUpFLEdBSkk7QUFRTCxDQVhEO0FBYUE7Ozs7Ozs7QUFLQUksUUFBUSxDQUFDQyxjQUFULEdBQTBCO0FBQ3hCQyxNQUFJLEVBQUUseUNBRGtCO0FBRXhCQyxVQUFRLEVBQUVDLE1BQU0sQ0FBQ0MsV0FBUCxHQUFxQkMsT0FBckIsQ0FBNkIsY0FB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LENBcUJKOztBQUNBLGFBQU87QUFBQ2pCLGNBQU0sRUFBRUE7QUFBVCxPQUFQO0FBQ0QsS0E1QkksQ0FBUDtBQThCRDtBQWhDYyxDQUFmLEUsQ0FrQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBOztBQUNBbkQsUUFBUSxDQUFDOE4sVUFBVCxHQUFzQixDQUFDcE0sT0FBRCxFQUFVeU0sUUFBVixLQUF1QjtBQUMzQ3pNLFNBQU8scUJBQVFBLE9BQVIsQ0FBUCxDQUQyQyxDQUczQzs7QUFDQSxNQUFJeU0sUUFBSixFQUFjO0FBQ1osVUFBTSxJQUFJOUwsS0FBSixDQUFVLG9FQUFWLENBQU47QUFDRDs7QUFFRCxTQUFPeUwsVUFBVSxDQUFDcE0sT0FBRCxDQUFqQjtBQUNELENBVEQsQyxDQVdBO0FBQ0E7QUFDQTs7O0FBQ0F0QixNQUFNLENBQUN1QixLQUFQLENBQWF5TSxZQUFiLENBQTBCLHlDQUExQixFQUMwQjtBQUFFQyxRQUFNLEVBQUUsSUFBVjtBQUFnQkMsUUFBTSxFQUFFO0FBQXhCLENBRDFCOztBQUVBbE8sTUFBTSxDQUFDdUIsS0FBUCxDQUFheU0sWUFBYixDQUEwQiwrQkFBMUIsRUFDMEI7QUFBRUMsUUFBTSxFQUFFLElBQVY7QUFBZ0JDLFFBQU0sRUFBRTtBQUF4QixDQUQxQixFIiwiZmlsZSI6Ii9wYWNrYWdlcy9hY2NvdW50cy1wYXNzd29yZC5qcyIsInNvdXJjZXNDb250ZW50IjpbImNvbnN0IGdyZWV0ID0gd2VsY29tZU1zZyA9PiAodXNlciwgdXJsKSA9PiB7XG4gICAgICBjb25zdCBncmVldGluZyA9ICh1c2VyLnByb2ZpbGUgJiYgdXNlci5wcm9maWxlLm5hbWUpID9cbiAgICAgICAgICAgIChgSGVsbG8gJHt1c2VyLnByb2ZpbGUubmFtZX0sYCkgOiBcIkhlbGxvLFwiO1xuICAgICAgcmV0dXJuIGAke2dyZWV0aW5nfVxuXG4ke3dlbGNvbWVNc2d9LCBzaW1wbHkgY2xpY2sgdGhlIGxpbmsgYmVsb3cuXG5cbiR7dXJsfVxuXG5UaGFua3MuXG5gO1xufTtcblxuLyoqXG4gKiBAc3VtbWFyeSBPcHRpb25zIHRvIGN1c3RvbWl6ZSBlbWFpbHMgc2VudCBmcm9tIHRoZSBBY2NvdW50cyBzeXN0ZW0uXG4gKiBAbG9jdXMgU2VydmVyXG4gKiBAaW1wb3J0RnJvbVBhY2thZ2UgYWNjb3VudHMtYmFzZVxuICovXG5BY2NvdW50cy5lbWFpbFRlbXBsYXRlcyA9IHtcbiAgZnJvbTogXCJBY2NvdW50cyBFeGFtcGxlIDxuby1yZXBseUBleGFtcGxlLmNvbT5cIixcbiAgc2l0ZU5hbWU6IE1ldGVvci5hYnNvbHV0ZVVybCgpLnJlcGxhY2UoL15odHRwcz86XFwvXFwvLywgJycpLnJlcGxhY2UoL1xcLyQvLCAnJyksXG5cbiAgcmVzZXRQYXNzd29yZDoge1xuICAgIHN1YmplY3Q6ICgpID0+IGBIb3cgdG8gcmVzZXQgeW91ciBwYXNzd29yZCBvbiAke0FjY291bnRzLmVtYWlsVGVtcGxhdGVzLnNpdGVOYW1lfWAsXG4gICAgdGV4dDogZ3JlZXQoXCJUbyByZXNldCB5b3VyIHBhc3N3b3JkXCIpLFxuICB9LFxuICB2ZXJpZnlFbWFpbDoge1xuICAgIHN1YmplY3Q6ICgpID0+IGBIb3cgdG8gdmVyaWZ5IGVtYWlsIGFkZHJlc3Mgb24gJHtBY2NvdW50cy5lbWFpbFRlbXBsYXRlcy5zaXRlTmFtZX1gLFxuICAgIHRleHQ6IGdyZWV0KFwiVG8gdmVyaWZ5IHlvdXIgYWNjb3VudCBlbWFpbFwiKSxcbiAgfSxcbiAgZW5yb2xsQWNjb3VudDoge1xuICAgIHN1YmplY3Q6ICgpID0+IGBBbiBhY2NvdW50IGhhcyBiZWVuIGNyZWF0ZWQgZm9yIHlvdSBvbiAke0FjY291bnRzLmVtYWlsVGVtcGxhdGVzLnNpdGVOYW1lfWAsXG4gICAgdGV4dDogZ3JlZXQoXCJUbyBzdGFydCB1c2luZyB0aGUgc2VydmljZVwiKSxcbiAgfSxcbn07XG4iLCIvLy8gQkNSWVBUXG5cbmNvbnN0IGJjcnlwdCA9IE5wbU1vZHVsZUJjcnlwdDtcbmNvbnN0IGJjcnlwdEhhc2ggPSBNZXRlb3Iud3JhcEFzeW5jKGJjcnlwdC5oYXNoKTtcbmNvbnN0IGJjcnlwdENvbXBhcmUgPSBNZXRlb3Iud3JhcEFzeW5jKGJjcnlwdC5jb21wYXJlKTtcblxuLy8gVXRpbGl0eSBmb3IgZ3JhYmJpbmcgdXNlclxuY29uc3QgZ2V0VXNlckJ5SWQgPSAoaWQsIG9wdGlvbnMpID0+IE1ldGVvci51c2Vycy5maW5kT25lKGlkLCBBY2NvdW50cy5fYWRkRGVmYXVsdEZpZWxkU2VsZWN0b3Iob3B0aW9ucykpO1xuXG4vLyBVc2VyIHJlY29yZHMgaGF2ZSBhICdzZXJ2aWNlcy5wYXNzd29yZC5iY3J5cHQnIGZpZWxkIG9uIHRoZW0gdG8gaG9sZFxuLy8gdGhlaXIgaGFzaGVkIHBhc3N3b3JkcyAodW5sZXNzIHRoZXkgaGF2ZSBhICdzZXJ2aWNlcy5wYXNzd29yZC5zcnAnXG4vLyBmaWVsZCwgaW4gd2hpY2ggY2FzZSB0aGV5IHdpbGwgYmUgdXBncmFkZWQgdG8gYmNyeXB0IHRoZSBuZXh0IHRpbWVcbi8vIHRoZXkgbG9nIGluKS5cbi8vXG4vLyBXaGVuIHRoZSBjbGllbnQgc2VuZHMgYSBwYXNzd29yZCB0byB0aGUgc2VydmVyLCBpdCBjYW4gZWl0aGVyIGJlIGFcbi8vIHN0cmluZyAodGhlIHBsYWludGV4dCBwYXNzd29yZCkgb3IgYW4gb2JqZWN0IHdpdGgga2V5cyAnZGlnZXN0JyBhbmRcbi8vICdhbGdvcml0aG0nIChtdXN0IGJlIFwic2hhLTI1NlwiIGZvciBub3cpLiBUaGUgTWV0ZW9yIGNsaWVudCBhbHdheXMgc2VuZHNcbi8vIHBhc3N3b3JkIG9iamVjdHMgeyBkaWdlc3Q6ICosIGFsZ29yaXRobTogXCJzaGEtMjU2XCIgfSwgYnV0IEREUCBjbGllbnRzXG4vLyB0aGF0IGRvbid0IGhhdmUgYWNjZXNzIHRvIFNIQSBjYW4ganVzdCBzZW5kIHBsYWludGV4dCBwYXNzd29yZHMgYXNcbi8vIHN0cmluZ3MuXG4vL1xuLy8gV2hlbiB0aGUgc2VydmVyIHJlY2VpdmVzIGEgcGxhaW50ZXh0IHBhc3N3b3JkIGFzIGEgc3RyaW5nLCBpdCBhbHdheXNcbi8vIGhhc2hlcyBpdCB3aXRoIFNIQTI1NiBiZWZvcmUgcGFzc2luZyBpdCBpbnRvIGJjcnlwdC4gV2hlbiB0aGUgc2VydmVyXG4vLyByZWNlaXZlcyBhIHBhc3N3b3JkIGFzIGFuIG9iamVjdCwgaXQgYXNzZXJ0cyB0aGF0IHRoZSBhbGdvcml0aG0gaXNcbi8vIFwic2hhLTI1NlwiIGFuZCB0aGVuIHBhc3NlcyB0aGUgZGlnZXN0IHRvIGJjcnlwdC5cblxuXG5BY2NvdW50cy5fYmNyeXB0Um91bmRzID0gKCkgPT4gQWNjb3VudHMuX29wdGlvbnMuYmNyeXB0Um91bmRzIHx8IDEwO1xuXG4vLyBHaXZlbiBhICdwYXNzd29yZCcgZnJvbSB0aGUgY2xpZW50LCBleHRyYWN0IHRoZSBzdHJpbmcgdGhhdCB3ZSBzaG91bGRcbi8vIGJjcnlwdC4gJ3Bhc3N3b3JkJyBjYW4gYmUgb25lIG9mOlxuLy8gIC0gU3RyaW5nICh0aGUgcGxhaW50ZXh0IHBhc3N3b3JkKVxuLy8gIC0gT2JqZWN0IHdpdGggJ2RpZ2VzdCcgYW5kICdhbGdvcml0aG0nIGtleXMuICdhbGdvcml0aG0nIG11c3QgYmUgXCJzaGEtMjU2XCIuXG4vL1xuY29uc3QgZ2V0UGFzc3dvcmRTdHJpbmcgPSBwYXNzd29yZCA9PiB7XG4gIGlmICh0eXBlb2YgcGFzc3dvcmQgPT09IFwic3RyaW5nXCIpIHtcbiAgICBwYXNzd29yZCA9IFNIQTI1NihwYXNzd29yZCk7XG4gIH0gZWxzZSB7IC8vICdwYXNzd29yZCcgaXMgYW4gb2JqZWN0XG4gICAgaWYgKHBhc3N3b3JkLmFsZ29yaXRobSAhPT0gXCJzaGEtMjU2XCIpIHtcbiAgICAgIHRocm93IG5ldyBFcnJvcihcIkludmFsaWQgcGFzc3dvcmQgaGFzaCBhbGdvcml0aG0uIFwiICtcbiAgICAgICAgICAgICAgICAgICAgICBcIk9ubHkgJ3NoYS0yNTYnIGlzIGFsbG93ZWQuXCIpO1xuICAgIH1cbiAgICBwYXNzd29yZCA9IHBhc3N3b3JkLmRpZ2VzdDtcbiAgfVxuICByZXR1cm4gcGFzc3dvcmQ7XG59O1xuXG4vLyBVc2UgYmNyeXB0IHRvIGhhc2ggdGhlIHBhc3N3b3JkIGZvciBzdG9yYWdlIGluIHRoZSBkYXRhYmFzZS5cbi8vIGBwYXNzd29yZGAgY2FuIGJlIGEgc3RyaW5nIChpbiB3aGljaCBjYXNlIGl0IHdpbGwgYmUgcnVuIHRocm91Z2hcbi8vIFNIQTI1NiBiZWZvcmUgYmNyeXB0KSBvciBhbiBvYmplY3Qgd2l0aCBwcm9wZXJ0aWVzIGBkaWdlc3RgIGFuZFxuLy8gYGFsZ29yaXRobWAgKGluIHdoaWNoIGNhc2Ugd2UgYmNyeXB0IGBwYXNzd29yZC5kaWdlc3RgKS5cbi8vXG5jb25zdCBoYXNoUGFzc3dvcmQgPSBwYXNzd29yZCA9PiB7XG4gIHBhc3N3b3JkID0gZ2V0UGFzc3dvcmRTdHJpbmcocGFzc3dvcmQpO1xuICByZXR1cm4gYmNyeXB0SGFzaChwYXNzd29yZCwgQWNjb3VudHMuX2JjcnlwdFJvdW5kcygpKTtcbn07XG5cbi8vIEV4dHJhY3QgdGhlIG51bWJlciBvZiByb3VuZHMgdXNlZCBpbiB0aGUgc3BlY2lmaWVkIGJjcnlwdCBoYXNoLlxuY29uc3QgZ2V0Um91bmRzRnJvbUJjcnlwdEhhc2ggPSBoYXNoID0+IHtcbiAgbGV0IHJvdW5kcztcbiAgaWYgKGhhc2gpIHtcbiAgICBjb25zdCBoYXNoU2VnbWVudHMgPSBoYXNoLnNwbGl0KCckJyk7XG4gICAgaWYgKGhhc2hTZWdtZW50cy5sZW5ndGggPiAyKSB7XG4gICAgICByb3VuZHMgPSBwYXJzZUludChoYXNoU2VnbWVudHNbMl0sIDEwKTtcbiAgICB9XG4gIH1cbiAgcmV0dXJuIHJvdW5kcztcbn07XG5cbi8vIENoZWNrIHdoZXRoZXIgdGhlIHByb3ZpZGVkIHBhc3N3b3JkIG1hdGNoZXMgdGhlIGJjcnlwdCdlZCBwYXNzd29yZCBpblxuLy8gdGhlIGRhdGFiYXNlIHVzZXIgcmVjb3JkLiBgcGFzc3dvcmRgIGNhbiBiZSBhIHN0cmluZyAoaW4gd2hpY2ggY2FzZVxuLy8gaXQgd2lsbCBiZSBydW4gdGhyb3VnaCBTSEEyNTYgYmVmb3JlIGJjcnlwdCkgb3IgYW4gb2JqZWN0IHdpdGhcbi8vIHByb3BlcnRpZXMgYGRpZ2VzdGAgYW5kIGBhbGdvcml0aG1gIChpbiB3aGljaCBjYXNlIHdlIGJjcnlwdFxuLy8gYHBhc3N3b3JkLmRpZ2VzdGApLlxuLy9cbi8vIFRoZSB1c2VyIHBhcmFtZXRlciBuZWVkcyBhdCBsZWFzdCB1c2VyLl9pZCBhbmQgdXNlci5zZXJ2aWNlc1xuQWNjb3VudHMuX2NoZWNrUGFzc3dvcmRVc2VyRmllbGRzID0ge19pZDogMSwgc2VydmljZXM6IDF9LFxuLy9cbkFjY291bnRzLl9jaGVja1Bhc3N3b3JkID0gKHVzZXIsIHBhc3N3b3JkKSA9PiB7XG4gIGNvbnN0IHJlc3VsdCA9IHtcbiAgICB1c2VySWQ6IHVzZXIuX2lkXG4gIH07XG5cbiAgY29uc3QgZm9ybWF0dGVkUGFzc3dvcmQgPSBnZXRQYXNzd29yZFN0cmluZyhwYXNzd29yZCk7XG4gIGNvbnN0IGhhc2ggPSB1c2VyLnNlcnZpY2VzLnBhc3N3b3JkLmJjcnlwdDtcbiAgY29uc3QgaGFzaFJvdW5kcyA9IGdldFJvdW5kc0Zyb21CY3J5cHRIYXNoKGhhc2gpO1xuXG4gIGlmICghIGJjcnlwdENvbXBhcmUoZm9ybWF0dGVkUGFzc3dvcmQsIGhhc2gpKSB7XG4gICAgcmVzdWx0LmVycm9yID0gaGFuZGxlRXJyb3IoXCJJbmNvcnJlY3QgcGFzc3dvcmRcIiwgZmFsc2UpO1xuICB9IGVsc2UgaWYgKGhhc2ggJiYgQWNjb3VudHMuX2JjcnlwdFJvdW5kcygpICE9IGhhc2hSb3VuZHMpIHtcbiAgICAvLyBUaGUgcGFzc3dvcmQgY2hlY2tzIG91dCwgYnV0IHRoZSB1c2VyJ3MgYmNyeXB0IGhhc2ggbmVlZHMgdG8gYmUgdXBkYXRlZC5cbiAgICBNZXRlb3IuZGVmZXIoKCkgPT4ge1xuICAgICAgTWV0ZW9yLnVzZXJzLnVwZGF0ZSh7IF9pZDogdXNlci5faWQgfSwge1xuICAgICAgICAkc2V0OiB7XG4gICAgICAgICAgJ3NlcnZpY2VzLnBhc3N3b3JkLmJjcnlwdCc6XG4gICAgICAgICAgICBiY3J5cHRIYXNoKGZvcm1hdHRlZFBhc3N3b3JkLCBBY2NvdW50cy5fYmNyeXB0Um91bmRzKCkpXG4gICAgICAgIH1cbiAgICAgIH0pO1xuICAgIH0pO1xuICB9XG5cbiAgcmV0dXJuIHJlc3VsdDtcbn07XG5jb25zdCBjaGVja1Bhc3N3b3JkID0gQWNjb3VudHMuX2NoZWNrUGFzc3dvcmQ7XG5cbi8vL1xuLy8vIEVSUk9SIEhBTkRMRVJcbi8vL1xuY29uc3QgaGFuZGxlRXJyb3IgPSAobXNnLCB0aHJvd0Vycm9yID0gdHJ1ZSkgPT4ge1xuICBjb25zdCBlcnJvciA9IG5ldyBNZXRlb3IuRXJyb3IoXG4gICAgNDAzLFxuICAgIEFjY291bnRzLl9vcHRpb25zLmFtYmlndW91c0Vycm9yTWVzc2FnZXNcbiAgICAgID8gXCJTb21ldGhpbmcgd2VudCB3cm9uZy4gUGxlYXNlIGNoZWNrIHlvdXIgY3JlZGVudGlhbHMuXCJcbiAgICAgIDogbXNnXG4gICk7XG4gIGlmICh0aHJvd0Vycm9yKSB7XG4gICAgdGhyb3cgZXJyb3I7XG4gIH1cbiAgcmV0dXJuIGVycm9yO1xufTtcblxuLy8vXG4vLy8gTE9HSU5cbi8vL1xuXG5BY2NvdW50cy5fZmluZFVzZXJCeVF1ZXJ5ID0gKHF1ZXJ5LCBvcHRpb25zKSA9PiB7XG4gIGxldCB1c2VyID0gbnVsbDtcblxuICBpZiAocXVlcnkuaWQpIHtcbiAgICAvLyBkZWZhdWx0IGZpZWxkIHNlbGVjdG9yIGlzIGFkZGVkIHdpdGhpbiBnZXRVc2VyQnlJZCgpXG4gICAgdXNlciA9IGdldFVzZXJCeUlkKHF1ZXJ5LmlkLCBvcHRpb25zKTtcbiAgfSBlbHNlIHtcbiAgICBvcHRpb25zID0gQWNjb3VudHMuX2FkZERlZmF1bHRGaWVsZFNlbGVjdG9yKG9wdGlvbnMpO1xuICAgIGxldCBmaWVsZE5hbWU7XG4gICAgbGV0IGZpZWxkVmFsdWU7XG4gICAgaWYgKHF1ZXJ5LnVzZXJuYW1lKSB7XG4gICAgICBmaWVsZE5hbWUgPSAndXNlcm5hbWUnO1xuICAgICAgZmllbGRWYWx1ZSA9IHF1ZXJ5LnVzZXJuYW1lO1xuICAgIH0gZWxzZSBpZiAocXVlcnkuZW1haWwpIHtcbiAgICAgIGZpZWxkTmFtZSA9ICdlbWFpbHMuYWRkcmVzcyc7XG4gICAgICBmaWVsZFZhbHVlID0gcXVlcnkuZW1haWw7XG4gICAgfSBlbHNlIHtcbiAgICAgIHRocm93IG5ldyBFcnJvcihcInNob3VsZG4ndCBoYXBwZW4gKHZhbGlkYXRpb24gbWlzc2VkIHNvbWV0aGluZylcIik7XG4gICAgfVxuICAgIGxldCBzZWxlY3RvciA9IHt9O1xuICAgIHNlbGVjdG9yW2ZpZWxkTmFtZV0gPSBmaWVsZFZhbHVlO1xuICAgIHVzZXIgPSBNZXRlb3IudXNlcnMuZmluZE9uZShzZWxlY3Rvciwgb3B0aW9ucyk7XG4gICAgLy8gSWYgdXNlciBpcyBub3QgZm91bmQsIHRyeSBhIGNhc2UgaW5zZW5zaXRpdmUgbG9va3VwXG4gICAgaWYgKCF1c2VyKSB7XG4gICAgICBzZWxlY3RvciA9IHNlbGVjdG9yRm9yRmFzdENhc2VJbnNlbnNpdGl2ZUxvb2t1cChmaWVsZE5hbWUsIGZpZWxkVmFsdWUpO1xuICAgICAgY29uc3QgY2FuZGlkYXRlVXNlcnMgPSBNZXRlb3IudXNlcnMuZmluZChzZWxlY3Rvciwgb3B0aW9ucykuZmV0Y2goKTtcbiAgICAgIC8vIE5vIG1hdGNoIGlmIG11bHRpcGxlIGNhbmRpZGF0ZXMgYXJlIGZvdW5kXG4gICAgICBpZiAoY2FuZGlkYXRlVXNlcnMubGVuZ3RoID09PSAxKSB7XG4gICAgICAgIHVzZXIgPSBjYW5kaWRhdGVVc2Vyc1swXTtcbiAgICAgIH1cbiAgICB9XG4gIH1cblxuICByZXR1cm4gdXNlcjtcbn07XG5cbi8qKlxuICogQHN1bW1hcnkgRmluZHMgdGhlIHVzZXIgd2l0aCB0aGUgc3BlY2lmaWVkIHVzZXJuYW1lLlxuICogRmlyc3QgdHJpZXMgdG8gbWF0Y2ggdXNlcm5hbWUgY2FzZSBzZW5zaXRpdmVseTsgaWYgdGhhdCBmYWlscywgaXRcbiAqIHRyaWVzIGNhc2UgaW5zZW5zaXRpdmVseTsgYnV0IGlmIG1vcmUgdGhhbiBvbmUgdXNlciBtYXRjaGVzIHRoZSBjYXNlXG4gKiBpbnNlbnNpdGl2ZSBzZWFyY2gsIGl0IHJldHVybnMgbnVsbC5cbiAqIEBsb2N1cyBTZXJ2ZXJcbiAqIEBwYXJhbSB7U3RyaW5nfSB1c2VybmFtZSBUaGUgdXNlcm5hbWUgdG8gbG9vayBmb3JcbiAqIEBwYXJhbSB7T2JqZWN0fSBbb3B0aW9uc11cbiAqIEBwYXJhbSB7TW9uZ29GaWVsZFNwZWNpZmllcn0gb3B0aW9ucy5maWVsZHMgRGljdGlvbmFyeSBvZiBmaWVsZHMgdG8gcmV0dXJuIG9yIGV4Y2x1ZGUuXG4gKiBAcmV0dXJucyB7T2JqZWN0fSBBIHVzZXIgaWYgZm91bmQsIGVsc2UgbnVsbFxuICogQGltcG9ydEZyb21QYWNrYWdlIGFjY291bnRzLWJhc2VcbiAqL1xuQWNjb3VudHMuZmluZFVzZXJCeVVzZXJuYW1lID1cbiAgKHVzZXJuYW1lLCBvcHRpb25zKSA9PiBBY2NvdW50cy5fZmluZFVzZXJCeVF1ZXJ5KHsgdXNlcm5hbWUgfSwgb3B0aW9ucyk7XG5cbi8qKlxuICogQHN1bW1hcnkgRmluZHMgdGhlIHVzZXIgd2l0aCB0aGUgc3BlY2lmaWVkIGVtYWlsLlxuICogRmlyc3QgdHJpZXMgdG8gbWF0Y2ggZW1haWwgY2FzZSBzZW5zaXRpdmVseTsgaWYgdGhhdCBmYWlscywgaXRcbiAqIHRyaWVzIGNhc2UgaW5zZW5zaXRpdmVseTsgYnV0IGlmIG1vcmUgdGhhbiBvbmUgdXNlciBtYXRjaGVzIHRoZSBjYXNlXG4gKiBpbnNlbnNpdGl2ZSBzZWFyY2gsIGl0IHJldHVybnMgbnVsbC5cbiAqIEBsb2N1cyBTZXJ2ZXJcbiAqIEBwYXJhbSB7U3RyaW5nfSBlbWFpbCBUaGUgZW1haWwgYWRkcmVzcyB0byBsb29rIGZvclxuICogQHBhcmFtIHtPYmplY3R9IFtvcHRpb25zXVxuICogQHBhcmFtIHtNb25nb0ZpZWxkU3BlY2lmaWVyfSBvcHRpb25zLmZpZWxkcyBEaWN0aW9uYXJ5IG9mIGZpZWxkcyB0byByZXR1cm4gb3IgZXhjbHVkZS5cbiAqIEByZXR1cm5zIHtPYmplY3R9IEEgdXNlciBpZiBmb3VuZCwgZWxzZSBudWxsXG4gKiBAaW1wb3J0RnJvbVBhY2thZ2UgYWNjb3VudHMtYmFzZVxuICovXG5BY2NvdW50cy5maW5kVXNlckJ5RW1haWwgPVxuICAoZW1haWwsIG9wdGlvbnMpID0+IEFjY291bnRzLl9maW5kVXNlckJ5UXVlcnkoeyBlbWFpbCB9LCBvcHRpb25zKTtcblxuLy8gR2VuZXJhdGVzIGEgTW9uZ29EQiBzZWxlY3RvciB0aGF0IGNhbiBiZSB1c2VkIHRvIHBlcmZvcm0gYSBmYXN0IGNhc2Vcbi8vIGluc2Vuc2l0aXZlIGxvb2t1cCBmb3IgdGhlIGdpdmVuIGZpZWxkTmFtZSBhbmQgc3RyaW5nLiBTaW5jZSBNb25nb0RCIGRvZXNcbi8vIG5vdCBzdXBwb3J0IGNhc2UgaW5zZW5zaXRpdmUgaW5kZXhlcywgYW5kIGNhc2UgaW5zZW5zaXRpdmUgcmVnZXggcXVlcmllc1xuLy8gYXJlIHNsb3csIHdlIGNvbnN0cnVjdCBhIHNldCBvZiBwcmVmaXggc2VsZWN0b3JzIGZvciBhbGwgcGVybXV0YXRpb25zIG9mXG4vLyB0aGUgZmlyc3QgNCBjaGFyYWN0ZXJzIG91cnNlbHZlcy4gV2UgZmlyc3QgYXR0ZW1wdCB0byBtYXRjaGluZyBhZ2FpbnN0XG4vLyB0aGVzZSwgYW5kIGJlY2F1c2UgJ3ByZWZpeCBleHByZXNzaW9uJyByZWdleCBxdWVyaWVzIGRvIHVzZSBpbmRleGVzIChzZWVcbi8vIGh0dHA6Ly9kb2NzLm1vbmdvZGIub3JnL3YyLjYvcmVmZXJlbmNlL29wZXJhdG9yL3F1ZXJ5L3JlZ2V4LyNpbmRleC11c2UpLFxuLy8gdGhpcyBoYXMgYmVlbiBmb3VuZCB0byBncmVhdGx5IGltcHJvdmUgcGVyZm9ybWFuY2UgKGZyb20gMTIwMG1zIHRvIDVtcyBpbiBhXG4vLyB0ZXN0IHdpdGggMS4wMDAuMDAwIHVzZXJzKS5cbmNvbnN0IHNlbGVjdG9yRm9yRmFzdENhc2VJbnNlbnNpdGl2ZUxvb2t1cCA9IChmaWVsZE5hbWUsIHN0cmluZykgPT4ge1xuICAvLyBQZXJmb3JtYW5jZSBzZWVtcyB0byBpbXByb3ZlIHVwIHRvIDQgcHJlZml4IGNoYXJhY3RlcnNcbiAgY29uc3QgcHJlZml4ID0gc3RyaW5nLnN1YnN0cmluZygwLCBNYXRoLm1pbihzdHJpbmcubGVuZ3RoLCA0KSk7XG4gIGNvbnN0IG9yQ2xhdXNlID0gZ2VuZXJhdGVDYXNlUGVybXV0YXRpb25zRm9yU3RyaW5nKHByZWZpeCkubWFwKFxuICAgIHByZWZpeFBlcm11dGF0aW9uID0+IHtcbiAgICAgIGNvbnN0IHNlbGVjdG9yID0ge307XG4gICAgICBzZWxlY3RvcltmaWVsZE5hbWVdID1cbiAgICAgICAgbmV3IFJlZ0V4cChgXiR7TWV0ZW9yLl9lc2NhcGVSZWdFeHAocHJlZml4UGVybXV0YXRpb24pfWApO1xuICAgICAgcmV0dXJuIHNlbGVjdG9yO1xuICAgIH0pO1xuICBjb25zdCBjYXNlSW5zZW5zaXRpdmVDbGF1c2UgPSB7fTtcbiAgY2FzZUluc2Vuc2l0aXZlQ2xhdXNlW2ZpZWxkTmFtZV0gPVxuICAgIG5ldyBSZWdFeHAoYF4ke01ldGVvci5fZXNjYXBlUmVnRXhwKHN0cmluZyl9JGAsICdpJylcbiAgcmV0dXJuIHskYW5kOiBbeyRvcjogb3JDbGF1c2V9LCBjYXNlSW5zZW5zaXRpdmVDbGF1c2VdfTtcbn1cblxuLy8gR2VuZXJhdGVzIHBlcm11dGF0aW9ucyBvZiBhbGwgY2FzZSB2YXJpYXRpb25zIG9mIGEgZ2l2ZW4gc3RyaW5nLlxuY29uc3QgZ2VuZXJhdGVDYXNlUGVybXV0YXRpb25zRm9yU3RyaW5nID0gc3RyaW5nID0+IHtcbiAgbGV0IHBlcm11dGF0aW9ucyA9IFsnJ107XG4gIGZvciAobGV0IGkgPSAwOyBpIDwgc3RyaW5nLmxlbmd0aDsgaSsrKSB7XG4gICAgY29uc3QgY2ggPSBzdHJpbmcuY2hhckF0KGkpO1xuICAgIHBlcm11dGF0aW9ucyA9IFtdLmNvbmNhdCguLi4ocGVybXV0YXRpb25zLm1hcChwcmVmaXggPT4ge1xuICAgICAgY29uc3QgbG93ZXJDYXNlQ2hhciA9IGNoLnRvTG93ZXJDYXNlKCk7XG4gICAgICBjb25zdCB1cHBlckNhc2VDaGFyID0gY2gudG9VcHBlckNhc2UoKTtcbiAgICAgIC8vIERvbid0IGFkZCB1bm5lY2Nlc2FyeSBwZXJtdXRhdGlvbnMgd2hlbiBjaCBpcyBub3QgYSBsZXR0ZXJcbiAgICAgIGlmIChsb3dlckNhc2VDaGFyID09PSB1cHBlckNhc2VDaGFyKSB7XG4gICAgICAgIHJldHVybiBbcHJlZml4ICsgY2hdO1xuICAgICAgfSBlbHNlIHtcbiAgICAgICAgcmV0dXJuIFtwcmVmaXggKyBsb3dlckNhc2VDaGFyLCBwcmVmaXggKyB1cHBlckNhc2VDaGFyXTtcbiAgICAgIH1cbiAgICB9KSkpO1xuICB9XG4gIHJldHVybiBwZXJtdXRhdGlvbnM7XG59XG5cbmNvbnN0IGNoZWNrRm9yQ2FzZUluc2Vuc2l0aXZlRHVwbGljYXRlcyA9IChmaWVsZE5hbWUsIGRpc3BsYXlOYW1lLCBmaWVsZFZhbHVlLCBvd25Vc2VySWQpID0+IHtcbiAgLy8gU29tZSB0ZXN0cyBuZWVkIHRoZSBhYmlsaXR5IHRvIGFkZCB1c2VycyB3aXRoIHRoZSBzYW1lIGNhc2UgaW5zZW5zaXRpdmVcbiAgLy8gdmFsdWUsIGhlbmNlIHRoZSBfc2tpcENhc2VJbnNlbnNpdGl2ZUNoZWNrc0ZvclRlc3QgY2hlY2tcbiAgY29uc3Qgc2tpcENoZWNrID0gT2JqZWN0LnByb3RvdHlwZS5oYXNPd25Qcm9wZXJ0eS5jYWxsKEFjY291bnRzLl9za2lwQ2FzZUluc2Vuc2l0aXZlQ2hlY2tzRm9yVGVzdCwgZmllbGRWYWx1ZSk7XG5cbiAgaWYgKGZpZWxkVmFsdWUgJiYgIXNraXBDaGVjaykge1xuICAgIGNvbnN0IG1hdGNoZWRVc2VycyA9IE1ldGVvci51c2Vycy5maW5kKFxuICAgICAgc2VsZWN0b3JGb3JGYXN0Q2FzZUluc2Vuc2l0aXZlTG9va3VwKGZpZWxkTmFtZSwgZmllbGRWYWx1ZSksXG4gICAgICB7XG4gICAgICAgIGZpZWxkczoge19pZDogMX0sXG4gICAgICAgIC8vIHdlIG9ubHkgbmVlZCBhIG1heGltdW0gb2YgMiB1c2VycyBmb3IgdGhlIGxvZ2ljIGJlbG93IHRvIHdvcmtcbiAgICAgICAgbGltaXQ6IDIsXG4gICAgICB9XG4gICAgKS5mZXRjaCgpO1xuXG4gICAgaWYgKG1hdGNoZWRVc2Vycy5sZW5ndGggPiAwICYmXG4gICAgICAgIC8vIElmIHdlIGRvbid0IGhhdmUgYSB1c2VySWQgeWV0LCBhbnkgbWF0Y2ggd2UgZmluZCBpcyBhIGR1cGxpY2F0ZVxuICAgICAgICAoIW93blVzZXJJZCB8fFxuICAgICAgICAvLyBPdGhlcndpc2UsIGNoZWNrIHRvIHNlZSBpZiB0aGVyZSBhcmUgbXVsdGlwbGUgbWF0Y2hlcyBvciBhIG1hdGNoXG4gICAgICAgIC8vIHRoYXQgaXMgbm90IHVzXG4gICAgICAgIChtYXRjaGVkVXNlcnMubGVuZ3RoID4gMSB8fCBtYXRjaGVkVXNlcnNbMF0uX2lkICE9PSBvd25Vc2VySWQpKSkge1xuICAgICAgaGFuZGxlRXJyb3IoYCR7ZGlzcGxheU5hbWV9IGFscmVhZHkgZXhpc3RzLmApO1xuICAgIH1cbiAgfVxufTtcblxuLy8gWFhYIG1heWJlIHRoaXMgYmVsb25ncyBpbiB0aGUgY2hlY2sgcGFja2FnZVxuY29uc3QgTm9uRW1wdHlTdHJpbmcgPSBNYXRjaC5XaGVyZSh4ID0+IHtcbiAgY2hlY2soeCwgU3RyaW5nKTtcbiAgcmV0dXJuIHgubGVuZ3RoID4gMDtcbn0pO1xuXG5jb25zdCB1c2VyUXVlcnlWYWxpZGF0b3IgPSBNYXRjaC5XaGVyZSh1c2VyID0+IHtcbiAgY2hlY2sodXNlciwge1xuICAgIGlkOiBNYXRjaC5PcHRpb25hbChOb25FbXB0eVN0cmluZyksXG4gICAgdXNlcm5hbWU6IE1hdGNoLk9wdGlvbmFsKE5vbkVtcHR5U3RyaW5nKSxcbiAgICBlbWFpbDogTWF0Y2guT3B0aW9uYWwoTm9uRW1wdHlTdHJpbmcpXG4gIH0pO1xuICBpZiAoT2JqZWN0LmtleXModXNlcikubGVuZ3RoICE9PSAxKVxuICAgIHRocm93IG5ldyBNYXRjaC5FcnJvcihcIlVzZXIgcHJvcGVydHkgbXVzdCBoYXZlIGV4YWN0bHkgb25lIGZpZWxkXCIpO1xuICByZXR1cm4gdHJ1ZTtcbn0pO1xuXG5jb25zdCBwYXNzd29yZFZhbGlkYXRvciA9IE1hdGNoLk9uZU9mKFxuICBTdHJpbmcsXG4gIHsgZGlnZXN0OiBTdHJpbmcsIGFsZ29yaXRobTogU3RyaW5nIH1cbik7XG5cbi8vIEhhbmRsZXIgdG8gbG9naW4gd2l0aCBhIHBhc3N3b3JkLlxuLy9cbi8vIFRoZSBNZXRlb3IgY2xpZW50IHNldHMgb3B0aW9ucy5wYXNzd29yZCB0byBhbiBvYmplY3Qgd2l0aCBrZXlzXG4vLyAnZGlnZXN0JyAoc2V0IHRvIFNIQTI1NihwYXNzd29yZCkpIGFuZCAnYWxnb3JpdGhtJyAoXCJzaGEtMjU2XCIpLlxuLy9cbi8vIEZvciBvdGhlciBERFAgY2xpZW50cyB3aGljaCBkb24ndCBoYXZlIGFjY2VzcyB0byBTSEEsIHRoZSBoYW5kbGVyXG4vLyBhbHNvIGFjY2VwdHMgdGhlIHBsYWludGV4dCBwYXNzd29yZCBpbiBvcHRpb25zLnBhc3N3b3JkIGFzIGEgc3RyaW5nLlxuLy9cbi8vIChJdCBtaWdodCBiZSBuaWNlIGlmIHNlcnZlcnMgY291bGQgdHVybiB0aGUgcGxhaW50ZXh0IHBhc3N3b3JkXG4vLyBvcHRpb24gb2ZmLiBPciBtYXliZSBpdCBzaG91bGQgYmUgb3B0LWluLCBub3Qgb3B0LW91dD9cbi8vIEFjY291bnRzLmNvbmZpZyBvcHRpb24/KVxuLy9cbi8vIE5vdGUgdGhhdCBuZWl0aGVyIHBhc3N3b3JkIG9wdGlvbiBpcyBzZWN1cmUgd2l0aG91dCBTU0wuXG4vL1xuQWNjb3VudHMucmVnaXN0ZXJMb2dpbkhhbmRsZXIoXCJwYXNzd29yZFwiLCBvcHRpb25zID0+IHtcbiAgaWYgKCEgb3B0aW9ucy5wYXNzd29yZCB8fCBvcHRpb25zLnNycClcbiAgICByZXR1cm4gdW5kZWZpbmVkOyAvLyBkb24ndCBoYW5kbGVcblxuICBjaGVjayhvcHRpb25zLCB7XG4gICAgdXNlcjogdXNlclF1ZXJ5VmFsaWRhdG9yLFxuICAgIHBhc3N3b3JkOiBwYXNzd29yZFZhbGlkYXRvclxuICB9KTtcblxuXG4gIGNvbnN0IHVzZXIgPSBBY2NvdW50cy5fZmluZFVzZXJCeVF1ZXJ5KG9wdGlvbnMudXNlciwge2ZpZWxkczoge1xuICAgIHNlcnZpY2VzOiAxLFxuICAgIC4uLkFjY291bnRzLl9jaGVja1Bhc3N3b3JkVXNlckZpZWxkcyxcbiAgfX0pO1xuICBpZiAoIXVzZXIpIHtcbiAgICBoYW5kbGVFcnJvcihcIlVzZXIgbm90IGZvdW5kXCIpO1xuICB9XG5cbiAgaWYgKCF1c2VyLnNlcnZpY2VzIHx8ICF1c2VyLnNlcnZpY2VzLnBhc3N3b3JkIHx8XG4gICAgICAhKHVzZXIuc2VydmljZXMucGFzc3dvcmQuYmNyeXB0IHx8IHVzZXIuc2VydmljZXMucGFzc3dvcmQuc3JwKSkge1xuICAgIGhhbmRsZUVycm9yKFwiVXNlciBoYXMgbm8gcGFzc3dvcmQgc2V0XCIpO1xuICB9XG5cbiAgaWYgKCF1c2VyLnNlcnZpY2VzLnBhc3N3b3JkLmJjcnlwdCkge1xuICAgIGlmICh0eXBlb2Ygb3B0aW9ucy5wYXNzd29yZCA9PT0gXCJzdHJpbmdcIikge1xuICAgICAgLy8gVGhlIGNsaWVudCBoYXMgcHJlc2VudGVkIGEgcGxhaW50ZXh0IHBhc3N3b3JkLCBhbmQgdGhlIHVzZXIgaXNcbiAgICAgIC8vIG5vdCB1cGdyYWRlZCB0byBiY3J5cHQgeWV0LiBXZSBkb24ndCBhdHRlbXB0IHRvIHRlbGwgdGhlIGNsaWVudFxuICAgICAgLy8gdG8gdXBncmFkZSB0byBiY3J5cHQsIGJlY2F1c2UgaXQgbWlnaHQgYmUgYSBzdGFuZGFsb25lIEREUFxuICAgICAgLy8gY2xpZW50IGRvZXNuJ3Qga25vdyBob3cgdG8gZG8gc3VjaCBhIHRoaW5nLlxuICAgICAgY29uc3QgdmVyaWZpZXIgPSB1c2VyLnNlcnZpY2VzLnBhc3N3b3JkLnNycDtcbiAgICAgIGNvbnN0IG5ld1ZlcmlmaWVyID0gU1JQLmdlbmVyYXRlVmVyaWZpZXIob3B0aW9ucy5wYXNzd29yZCwge1xuICAgICAgICBpZGVudGl0eTogdmVyaWZpZXIuaWRlbnRpdHksIHNhbHQ6IHZlcmlmaWVyLnNhbHR9KTtcblxuICAgICAgaWYgKHZlcmlmaWVyLnZlcmlmaWVyICE9PSBuZXdWZXJpZmllci52ZXJpZmllcikge1xuICAgICAgICByZXR1cm4ge1xuICAgICAgICAgIHVzZXJJZDogQWNjb3VudHMuX29wdGlvbnMuYW1iaWd1b3VzRXJyb3JNZXNzYWdlcyA/IG51bGwgOiB1c2VyLl9pZCxcbiAgICAgICAgICBlcnJvcjogaGFuZGxlRXJyb3IoXCJJbmNvcnJlY3QgcGFzc3dvcmRcIiwgZmFsc2UpXG4gICAgICAgIH07XG4gICAgICB9XG5cbiAgICAgIHJldHVybiB7dXNlcklkOiB1c2VyLl9pZH07XG4gICAgfSBlbHNlIHtcbiAgICAgIC8vIFRlbGwgdGhlIGNsaWVudCB0byB1c2UgdGhlIFNSUCB1cGdyYWRlIHByb2Nlc3MuXG4gICAgICB0aHJvdyBuZXcgTWV0ZW9yLkVycm9yKDQwMCwgXCJvbGQgcGFzc3dvcmQgZm9ybWF0XCIsIEVKU09OLnN0cmluZ2lmeSh7XG4gICAgICAgIGZvcm1hdDogJ3NycCcsXG4gICAgICAgIGlkZW50aXR5OiB1c2VyLnNlcnZpY2VzLnBhc3N3b3JkLnNycC5pZGVudGl0eVxuICAgICAgfSkpO1xuICAgIH1cbiAgfVxuXG4gIHJldHVybiBjaGVja1Bhc3N3b3JkKFxuICAgIHVzZXIsXG4gICAgb3B0aW9ucy5wYXNzd29yZFxuICApO1xufSk7XG5cbi8vIEhhbmRsZXIgdG8gbG9naW4gdXNpbmcgdGhlIFNSUCB1cGdyYWRlIHBhdGguIFRvIHVzZSB0aGlzIGxvZ2luXG4vLyBoYW5kbGVyLCB0aGUgY2xpZW50IG11c3QgcHJvdmlkZTpcbi8vICAgLSBzcnA6IEgoaWRlbnRpdHkgKyBcIjpcIiArIHBhc3N3b3JkKVxuLy8gICAtIHBhc3N3b3JkOiBhIHN0cmluZyBvciBhbiBvYmplY3Qgd2l0aCBwcm9wZXJ0aWVzICdkaWdlc3QnIGFuZCAnYWxnb3JpdGhtJ1xuLy9cbi8vIFdlIHVzZSBgb3B0aW9ucy5zcnBgIHRvIHZlcmlmeSB0aGF0IHRoZSBjbGllbnQga25vd3MgdGhlIGNvcnJlY3Rcbi8vIHBhc3N3b3JkIHdpdGhvdXQgZG9pbmcgYSBmdWxsIFNSUCBmbG93LiBPbmNlIHdlJ3ZlIGNoZWNrZWQgdGhhdCwgd2Vcbi8vIHVwZ3JhZGUgdGhlIHVzZXIgdG8gYmNyeXB0IGFuZCByZW1vdmUgdGhlIFNSUCBpbmZvcm1hdGlvbiBmcm9tIHRoZVxuLy8gdXNlciBkb2N1bWVudC5cbi8vXG4vLyBUaGUgY2xpZW50IGVuZHMgdXAgdXNpbmcgdGhpcyBsb2dpbiBoYW5kbGVyIGFmdGVyIHRyeWluZyB0aGUgbm9ybWFsXG4vLyBsb2dpbiBoYW5kbGVyIChhYm92ZSksIHdoaWNoIHRocm93cyBhbiBlcnJvciB0ZWxsaW5nIHRoZSBjbGllbnQgdG9cbi8vIHRyeSB0aGUgU1JQIHVwZ3JhZGUgcGF0aC5cbi8vXG4vLyBYWFggQ09NUEFUIFdJVEggMC44LjEuM1xuQWNjb3VudHMucmVnaXN0ZXJMb2dpbkhhbmRsZXIoXCJwYXNzd29yZFwiLCBvcHRpb25zID0+IHtcbiAgaWYgKCFvcHRpb25zLnNycCB8fCAhb3B0aW9ucy5wYXNzd29yZCkge1xuICAgIHJldHVybiB1bmRlZmluZWQ7IC8vIGRvbid0IGhhbmRsZVxuICB9XG5cbiAgY2hlY2sob3B0aW9ucywge1xuICAgIHVzZXI6IHVzZXJRdWVyeVZhbGlkYXRvcixcbiAgICBzcnA6IFN0cmluZyxcbiAgICBwYXNzd29yZDogcGFzc3dvcmRWYWxpZGF0b3JcbiAgfSk7XG5cbiAgY29uc3QgdXNlciA9IEFjY291bnRzLl9maW5kVXNlckJ5UXVlcnkob3B0aW9ucy51c2VyLCB7ZmllbGRzOiB7XG4gICAgc2VydmljZXM6IDEsXG4gICAgLi4uQWNjb3VudHMuX2NoZWNrUGFzc3dvcmRVc2VyRmllbGRzLFxuICB9fSk7XG4gIGlmICghdXNlcikge1xuICAgIGhhbmRsZUVycm9yKFwiVXNlciBub3QgZm91bmRcIik7XG4gIH1cblxuICAvLyBDaGVjayB0byBzZWUgaWYgYW5vdGhlciBzaW11bHRhbmVvdXMgbG9naW4gaGFzIGFscmVhZHkgdXBncmFkZWRcbiAgLy8gdGhlIHVzZXIgcmVjb3JkIHRvIGJjcnlwdC5cbiAgaWYgKHVzZXIuc2VydmljZXMgJiYgdXNlci5zZXJ2aWNlcy5wYXNzd29yZCAmJiB1c2VyLnNlcnZpY2VzLnBhc3N3b3JkLmJjcnlwdCkge1xuICAgIHJldHVybiBjaGVja1Bhc3N3b3JkKHVzZXIsIG9wdGlvbnMucGFzc3dvcmQpO1xuICB9XG5cbiAgaWYgKCEodXNlci5zZXJ2aWNlcyAmJiB1c2VyLnNlcnZpY2VzLnBhc3N3b3JkICYmIHVzZXIuc2VydmljZXMucGFzc3dvcmQuc3JwKSkge1xuICAgIGhhbmRsZUVycm9yKFwiVXNlciBoYXMgbm8gcGFzc3dvcmQgc2V0XCIpO1xuICB9XG5cbiAgY29uc3QgdjEgPSB1c2VyLnNlcnZpY2VzLnBhc3N3b3JkLnNycC52ZXJpZmllcjtcbiAgY29uc3QgdjIgPSBTUlAuZ2VuZXJhdGVWZXJpZmllcihcbiAgICBudWxsLFxuICAgIHtcbiAgICAgIGhhc2hlZElkZW50aXR5QW5kUGFzc3dvcmQ6IG9wdGlvbnMuc3JwLFxuICAgICAgc2FsdDogdXNlci5zZXJ2aWNlcy5wYXNzd29yZC5zcnAuc2FsdFxuICAgIH1cbiAgKS52ZXJpZmllcjtcbiAgaWYgKHYxICE9PSB2Mikge1xuICAgIHJldHVybiB7XG4gICAgICB1c2VySWQ6IEFjY291bnRzLl9vcHRpb25zLmFtYmlndW91c0Vycm9yTWVzc2FnZXMgPyBudWxsIDogdXNlci5faWQsXG4gICAgICBlcnJvcjogaGFuZGxlRXJyb3IoXCJJbmNvcnJlY3QgcGFzc3dvcmRcIiwgZmFsc2UpXG4gICAgfTtcbiAgfVxuXG4gIC8vIFVwZ3JhZGUgdG8gYmNyeXB0IG9uIHN1Y2Nlc3NmdWwgbG9naW4uXG4gIGNvbnN0IHNhbHRlZCA9IGhhc2hQYXNzd29yZChvcHRpb25zLnBhc3N3b3JkKTtcbiAgTWV0ZW9yLnVzZXJzLnVwZGF0ZShcbiAgICB1c2VyLl9pZCxcbiAgICB7XG4gICAgICAkdW5zZXQ6IHsgJ3NlcnZpY2VzLnBhc3N3b3JkLnNycCc6IDEgfSxcbiAgICAgICRzZXQ6IHsgJ3NlcnZpY2VzLnBhc3N3b3JkLmJjcnlwdCc6IHNhbHRlZCB9XG4gICAgfVxuICApO1xuXG4gIHJldHVybiB7dXNlcklkOiB1c2VyLl9pZH07XG59KTtcblxuXG4vLy9cbi8vLyBDSEFOR0lOR1xuLy8vXG5cbi8qKlxuICogQHN1bW1hcnkgQ2hhbmdlIGEgdXNlcidzIHVzZXJuYW1lLiBVc2UgdGhpcyBpbnN0ZWFkIG9mIHVwZGF0aW5nIHRoZVxuICogZGF0YWJhc2UgZGlyZWN0bHkuIFRoZSBvcGVyYXRpb24gd2lsbCBmYWlsIGlmIHRoZXJlIGlzIGFuIGV4aXN0aW5nIHVzZXJcbiAqIHdpdGggYSB1c2VybmFtZSBvbmx5IGRpZmZlcmluZyBpbiBjYXNlLlxuICogQGxvY3VzIFNlcnZlclxuICogQHBhcmFtIHtTdHJpbmd9IHVzZXJJZCBUaGUgSUQgb2YgdGhlIHVzZXIgdG8gdXBkYXRlLlxuICogQHBhcmFtIHtTdHJpbmd9IG5ld1VzZXJuYW1lIEEgbmV3IHVzZXJuYW1lIGZvciB0aGUgdXNlci5cbiAqIEBpbXBvcnRGcm9tUGFja2FnZSBhY2NvdW50cy1iYXNlXG4gKi9cbkFjY291bnRzLnNldFVzZXJuYW1lID0gKHVzZXJJZCwgbmV3VXNlcm5hbWUpID0+IHtcbiAgY2hlY2sodXNlcklkLCBOb25FbXB0eVN0cmluZyk7XG4gIGNoZWNrKG5ld1VzZXJuYW1lLCBOb25FbXB0eVN0cmluZyk7XG5cbiAgY29uc3QgdXNlciA9IGdldFVzZXJCeUlkKHVzZXJJZCwge2ZpZWxkczoge1xuICAgIHVzZXJuYW1lOiAxLFxuICB9fSk7XG4gIGlmICghdXNlcikge1xuICAgIGhhbmRsZUVycm9yKFwiVXNlciBub3QgZm91bmRcIik7XG4gIH1cblxuICBjb25zdCBvbGRVc2VybmFtZSA9IHVzZXIudXNlcm5hbWU7XG5cbiAgLy8gUGVyZm9ybSBhIGNhc2UgaW5zZW5zaXRpdmUgY2hlY2sgZm9yIGR1cGxpY2F0ZXMgYmVmb3JlIHVwZGF0ZVxuICBjaGVja0ZvckNhc2VJbnNlbnNpdGl2ZUR1cGxpY2F0ZXMoJ3VzZXJuYW1lJywgJ1VzZXJuYW1lJywgbmV3VXNlcm5hbWUsIHVzZXIuX2lkKTtcblxuICBNZXRlb3IudXNlcnMudXBkYXRlKHtfaWQ6IHVzZXIuX2lkfSwgeyRzZXQ6IHt1c2VybmFtZTogbmV3VXNlcm5hbWV9fSk7XG5cbiAgLy8gUGVyZm9ybSBhbm90aGVyIGNoZWNrIGFmdGVyIHVwZGF0ZSwgaW4gY2FzZSBhIG1hdGNoaW5nIHVzZXIgaGFzIGJlZW5cbiAgLy8gaW5zZXJ0ZWQgaW4gdGhlIG1lYW50aW1lXG4gIHRyeSB7XG4gICAgY2hlY2tGb3JDYXNlSW5zZW5zaXRpdmVEdXBsaWNhdGVzKCd1c2VybmFtZScsICdVc2VybmFtZScsIG5ld1VzZXJuYW1lLCB1c2VyLl9pZCk7XG4gIH0gY2F0Y2ggKGV4KSB7XG4gICAgLy8gVW5kbyB1cGRhdGUgaWYgdGhlIGNoZWNrIGZhaWxzXG4gICAgTWV0ZW9yLnVzZXJzLnVwZGF0ZSh7X2lkOiB1c2VyLl9pZH0sIHskc2V0OiB7dXNlcm5hbWU6IG9sZFVzZXJuYW1lfX0pO1xuICAgIHRocm93IGV4O1xuICB9XG59O1xuXG4vLyBMZXQgdGhlIHVzZXIgY2hhbmdlIHRoZWlyIG93biBwYXNzd29yZCBpZiB0aGV5IGtub3cgdGhlIG9sZFxuLy8gcGFzc3dvcmQuIGBvbGRQYXNzd29yZGAgYW5kIGBuZXdQYXNzd29yZGAgc2hvdWxkIGJlIG9iamVjdHMgd2l0aCBrZXlzXG4vLyBgZGlnZXN0YCBhbmQgYGFsZ29yaXRobWAgKHJlcHJlc2VudGluZyB0aGUgU0hBMjU2IG9mIHRoZSBwYXNzd29yZCkuXG4vL1xuLy8gWFhYIENPTVBBVCBXSVRIIDAuOC4xLjNcbi8vIExpa2UgdGhlIGxvZ2luIG1ldGhvZCwgaWYgdGhlIHVzZXIgaGFzbid0IGJlZW4gdXBncmFkZWQgZnJvbSBTUlAgdG9cbi8vIGJjcnlwdCB5ZXQsIHRoZW4gdGhpcyBtZXRob2Qgd2lsbCB0aHJvdyBhbiAnb2xkIHBhc3N3b3JkIGZvcm1hdCdcbi8vIGVycm9yLiBUaGUgY2xpZW50IHNob3VsZCBjYWxsIHRoZSBTUlAgdXBncmFkZSBsb2dpbiBoYW5kbGVyIGFuZCB0aGVuXG4vLyByZXRyeSB0aGlzIG1ldGhvZCBhZ2Fpbi5cbi8vXG4vLyBVTkxJS0UgdGhlIGxvZ2luIG1ldGhvZCwgdGhlcmUgaXMgbm8gd2F5IHRvIGF2b2lkIGdldHRpbmcgU1JQIHVwZ3JhZGVcbi8vIGVycm9ycyB0aHJvd24uIFRoZSByZWFzb25pbmcgZm9yIHRoaXMgaXMgdGhhdCBjbGllbnRzIHVzaW5nIHRoaXNcbi8vIG1ldGhvZCBkaXJlY3RseSB3aWxsIG5lZWQgdG8gYmUgdXBkYXRlZCBhbnl3YXkgYmVjYXVzZSB3ZSBubyBsb25nZXJcbi8vIHN1cHBvcnQgdGhlIFNSUCBmbG93IHRoYXQgdGhleSB3b3VsZCBoYXZlIGJlZW4gZG9pbmcgdG8gdXNlIHRoaXNcbi8vIG1ldGhvZCBwcmV2aW91c2x5LlxuTWV0ZW9yLm1ldGhvZHMoe2NoYW5nZVBhc3N3b3JkOiBmdW5jdGlvbiAob2xkUGFzc3dvcmQsIG5ld1Bhc3N3b3JkKSB7XG4gIGNoZWNrKG9sZFBhc3N3b3JkLCBwYXNzd29yZFZhbGlkYXRvcik7XG4gIGNoZWNrKG5ld1Bhc3N3b3JkLCBwYXNzd29yZFZhbGlkYXRvcik7XG5cbiAgaWYgKCF0aGlzLnVzZXJJZCkge1xuICAgIHRocm93IG5ldyBNZXRlb3IuRXJyb3IoNDAxLCBcIk11c3QgYmUgbG9nZ2VkIGluXCIpO1xuICB9XG5cbiAgY29uc3QgdXNlciA9IGdldFVzZXJCeUlkKHRoaXMudXNlcklkLCB7ZmllbGRzOiB7XG4gICAgc2VydmljZXM6IDEsXG4gICAgLi4uQWNjb3VudHMuX2NoZWNrUGFzc3dvcmRVc2VyRmllbGRzLFxuICB9fSk7XG4gIGlmICghdXNlcikge1xuICAgIGhhbmRsZUVycm9yKFwiVXNlciBub3QgZm91bmRcIik7XG4gIH1cblxuICBpZiAoIXVzZXIuc2VydmljZXMgfHwgIXVzZXIuc2VydmljZXMucGFzc3dvcmQgfHxcbiAgICAgICghdXNlci5zZXJ2aWNlcy5wYXNzd29yZC5iY3J5cHQgJiYgIXVzZXIuc2VydmljZXMucGFzc3dvcmQuc3JwKSkge1xuICAgIGhhbmRsZUVycm9yKFwiVXNlciBoYXMgbm8gcGFzc3dvcmQgc2V0XCIpO1xuICB9XG5cbiAgaWYgKCEgdXNlci5zZXJ2aWNlcy5wYXNzd29yZC5iY3J5cHQpIHtcbiAgICB0aHJvdyBuZXcgTWV0ZW9yLkVycm9yKDQwMCwgXCJvbGQgcGFzc3dvcmQgZm9ybWF0XCIsIEVKU09OLnN0cmluZ2lmeSh7XG4gICAgICBmb3JtYXQ6ICdzcnAnLFxuICAgICAgaWRlbnRpdHk6IHVzZXIuc2VydmljZXMucGFzc3dvcmQuc3JwLmlkZW50aXR5XG4gICAgfSkpO1xuICB9XG5cbiAgY29uc3QgcmVzdWx0ID0gY2hlY2tQYXNzd29yZCh1c2VyLCBvbGRQYXNzd29yZCk7XG4gIGlmIChyZXN1bHQuZXJyb3IpIHtcbiAgICB0aHJvdyByZXN1bHQuZXJyb3I7XG4gIH1cblxuICBjb25zdCBoYXNoZWQgPSBoYXNoUGFzc3dvcmQobmV3UGFzc3dvcmQpO1xuXG4gIC8vIEl0IHdvdWxkIGJlIGJldHRlciBpZiB0aGlzIHJlbW92ZWQgQUxMIGV4aXN0aW5nIHRva2VucyBhbmQgcmVwbGFjZWRcbiAgLy8gdGhlIHRva2VuIGZvciB0aGUgY3VycmVudCBjb25uZWN0aW9uIHdpdGggYSBuZXcgb25lLCBidXQgdGhhdCB3b3VsZFxuICAvLyBiZSB0cmlja3ksIHNvIHdlJ2xsIHNldHRsZSBmb3IganVzdCByZXBsYWNpbmcgYWxsIHRva2VucyBvdGhlciB0aGFuXG4gIC8vIHRoZSBvbmUgZm9yIHRoZSBjdXJyZW50IGNvbm5lY3Rpb24uXG4gIGNvbnN0IGN1cnJlbnRUb2tlbiA9IEFjY291bnRzLl9nZXRMb2dpblRva2VuKHRoaXMuY29ubmVjdGlvbi5pZCk7XG4gIE1ldGVvci51c2Vycy51cGRhdGUoXG4gICAgeyBfaWQ6IHRoaXMudXNlcklkIH0sXG4gICAge1xuICAgICAgJHNldDogeyAnc2VydmljZXMucGFzc3dvcmQuYmNyeXB0JzogaGFzaGVkIH0sXG4gICAgICAkcHVsbDoge1xuICAgICAgICAnc2VydmljZXMucmVzdW1lLmxvZ2luVG9rZW5zJzogeyBoYXNoZWRUb2tlbjogeyAkbmU6IGN1cnJlbnRUb2tlbiB9IH1cbiAgICAgIH0sXG4gICAgICAkdW5zZXQ6IHsgJ3NlcnZpY2VzLnBhc3N3b3JkLnJlc2V0JzogMSB9XG4gICAgfVxuICApO1xuXG4gIHJldHVybiB7cGFzc3dvcmRDaGFuZ2VkOiB0cnVlfTtcbn19KTtcblxuXG4vLyBGb3JjZSBjaGFuZ2UgdGhlIHVzZXJzIHBhc3N3b3JkLlxuXG4vKipcbiAqIEBzdW1tYXJ5IEZvcmNpYmx5IGNoYW5nZSB0aGUgcGFzc3dvcmQgZm9yIGEgdXNlci5cbiAqIEBsb2N1cyBTZXJ2ZXJcbiAqIEBwYXJhbSB7U3RyaW5nfSB1c2VySWQgVGhlIGlkIG9mIHRoZSB1c2VyIHRvIHVwZGF0ZS5cbiAqIEBwYXJhbSB7U3RyaW5nfSBuZXdQYXNzd29yZCBBIG5ldyBwYXNzd29yZCBmb3IgdGhlIHVzZXIuXG4gKiBAcGFyYW0ge09iamVjdH0gW29wdGlvbnNdXG4gKiBAcGFyYW0ge09iamVjdH0gb3B0aW9ucy5sb2dvdXQgTG9nb3V0IGFsbCBjdXJyZW50IGNvbm5lY3Rpb25zIHdpdGggdGhpcyB1c2VySWQgKGRlZmF1bHQ6IHRydWUpXG4gKiBAaW1wb3J0RnJvbVBhY2thZ2UgYWNjb3VudHMtYmFzZVxuICovXG5BY2NvdW50cy5zZXRQYXNzd29yZCA9ICh1c2VySWQsIG5ld1BsYWludGV4dFBhc3N3b3JkLCBvcHRpb25zKSA9PiB7XG4gIG9wdGlvbnMgPSB7IGxvZ291dDogdHJ1ZSAsIC4uLm9wdGlvbnMgfTtcblxuICBjb25zdCB1c2VyID0gZ2V0VXNlckJ5SWQodXNlcklkLCB7ZmllbGRzOiB7X2lkOiAxfX0pO1xuICBpZiAoIXVzZXIpIHtcbiAgICB0aHJvdyBuZXcgTWV0ZW9yLkVycm9yKDQwMywgXCJVc2VyIG5vdCBmb3VuZFwiKTtcbiAgfVxuXG4gIGNvbnN0IHVwZGF0ZSA9IHtcbiAgICAkdW5zZXQ6IHtcbiAgICAgICdzZXJ2aWNlcy5wYXNzd29yZC5zcnAnOiAxLCAvLyBYWFggQ09NUEFUIFdJVEggMC44LjEuM1xuICAgICAgJ3NlcnZpY2VzLnBhc3N3b3JkLnJlc2V0JzogMVxuICAgIH0sXG4gICAgJHNldDogeydzZXJ2aWNlcy5wYXNzd29yZC5iY3J5cHQnOiBoYXNoUGFzc3dvcmQobmV3UGxhaW50ZXh0UGFzc3dvcmQpfVxuICB9O1xuXG4gIGlmIChvcHRpb25zLmxvZ291dCkge1xuICAgIHVwZGF0ZS4kdW5zZXRbJ3NlcnZpY2VzLnJlc3VtZS5sb2dpblRva2VucyddID0gMTtcbiAgfVxuXG4gIE1ldGVvci51c2Vycy51cGRhdGUoe19pZDogdXNlci5faWR9LCB1cGRhdGUpO1xufTtcblxuXG4vLy9cbi8vLyBSRVNFVFRJTkcgVklBIEVNQUlMXG4vLy9cblxuLy8gVXRpbGl0eSBmb3IgcGx1Y2tpbmcgYWRkcmVzc2VzIGZyb20gZW1haWxzXG5jb25zdCBwbHVja0FkZHJlc3NlcyA9IChlbWFpbHMgPSBbXSkgPT4gZW1haWxzLm1hcChlbWFpbCA9PiBlbWFpbC5hZGRyZXNzKTtcblxuLy8gTWV0aG9kIGNhbGxlZCBieSBhIHVzZXIgdG8gcmVxdWVzdCBhIHBhc3N3b3JkIHJlc2V0IGVtYWlsLiBUaGlzIGlzXG4vLyB0aGUgc3RhcnQgb2YgdGhlIHJlc2V0IHByb2Nlc3MuXG5NZXRlb3IubWV0aG9kcyh7Zm9yZ290UGFzc3dvcmQ6IG9wdGlvbnMgPT4ge1xuICBjaGVjayhvcHRpb25zLCB7ZW1haWw6IFN0cmluZ30pO1xuXG4gIGNvbnN0IHVzZXIgPSBBY2NvdW50cy5maW5kVXNlckJ5RW1haWwob3B0aW9ucy5lbWFpbCwge2ZpZWxkczoge2VtYWlsczogMX19KTtcbiAgaWYgKCF1c2VyKSB7XG4gICAgaGFuZGxlRXJyb3IoXCJVc2VyIG5vdCBmb3VuZFwiKTtcbiAgfVxuXG4gIGNvbnN0IGVtYWlscyA9IHBsdWNrQWRkcmVzc2VzKHVzZXIuZW1haWxzKTtcbiAgY29uc3QgY2FzZVNlbnNpdGl2ZUVtYWlsID0gZW1haWxzLmZpbmQoXG4gICAgZW1haWwgPT4gZW1haWwudG9Mb3dlckNhc2UoKSA9PT0gb3B0aW9ucy5lbWFpbC50b0xvd2VyQ2FzZSgpXG4gICk7XG5cbiAgQWNjb3VudHMuc2VuZFJlc2V0UGFzc3dvcmRFbWFpbCh1c2VyLl9pZCwgY2FzZVNlbnNpdGl2ZUVtYWlsKTtcbn19KTtcblxuLyoqXG4gKiBAc3VtbWFyeSBHZW5lcmF0ZXMgYSByZXNldCB0b2tlbiBhbmQgc2F2ZXMgaXQgaW50byB0aGUgZGF0YWJhc2UuXG4gKiBAbG9jdXMgU2VydmVyXG4gKiBAcGFyYW0ge1N0cmluZ30gdXNlcklkIFRoZSBpZCBvZiB0aGUgdXNlciB0byBnZW5lcmF0ZSB0aGUgcmVzZXQgdG9rZW4gZm9yLlxuICogQHBhcmFtIHtTdHJpbmd9IGVtYWlsIFdoaWNoIGFkZHJlc3Mgb2YgdGhlIHVzZXIgdG8gZ2VuZXJhdGUgdGhlIHJlc2V0IHRva2VuIGZvci4gVGhpcyBhZGRyZXNzIG11c3QgYmUgaW4gdGhlIHVzZXIncyBgZW1haWxzYCBsaXN0LiBJZiBgbnVsbGAsIGRlZmF1bHRzIHRvIHRoZSBmaXJzdCBlbWFpbCBpbiB0aGUgbGlzdC5cbiAqIEBwYXJhbSB7U3RyaW5nfSByZWFzb24gYHJlc2V0UGFzc3dvcmRgIG9yIGBlbnJvbGxBY2NvdW50YC5cbiAqIEBwYXJhbSB7T2JqZWN0fSBbZXh0cmFUb2tlbkRhdGFdIE9wdGlvbmFsIGFkZGl0aW9uYWwgZGF0YSB0byBiZSBhZGRlZCBpbnRvIHRoZSB0b2tlbiByZWNvcmQuXG4gKiBAcmV0dXJucyB7T2JqZWN0fSBPYmplY3Qgd2l0aCB7ZW1haWwsIHVzZXIsIHRva2VufSB2YWx1ZXMuXG4gKiBAaW1wb3J0RnJvbVBhY2thZ2UgYWNjb3VudHMtYmFzZVxuICovXG5BY2NvdW50cy5nZW5lcmF0ZVJlc2V0VG9rZW4gPSAodXNlcklkLCBlbWFpbCwgcmVhc29uLCBleHRyYVRva2VuRGF0YSkgPT4ge1xuICAvLyBNYWtlIHN1cmUgdGhlIHVzZXIgZXhpc3RzLCBhbmQgZW1haWwgaXMgb25lIG9mIHRoZWlyIGFkZHJlc3Nlcy5cbiAgLy8gRG9uJ3QgbGltaXQgdGhlIGZpZWxkcyBpbiB0aGUgdXNlciBvYmplY3Qgc2luY2UgdGhlIHVzZXIgaXMgcmV0dXJuZWRcbiAgLy8gYnkgdGhlIGZ1bmN0aW9uIGFuZCBzb21lIG90aGVyIGZpZWxkcyBtaWdodCBiZSB1c2VkIGVsc2V3aGVyZS5cbiAgY29uc3QgdXNlciA9IGdldFVzZXJCeUlkKHVzZXJJZCk7XG4gIGlmICghdXNlcikge1xuICAgIGhhbmRsZUVycm9yKFwiQ2FuJ3QgZmluZCB1c2VyXCIpO1xuICB9XG5cbiAgLy8gcGljayB0aGUgZmlyc3QgZW1haWwgaWYgd2Ugd2VyZW4ndCBwYXNzZWQgYW4gZW1haWwuXG4gIGlmICghZW1haWwgJiYgdXNlci5lbWFpbHMgJiYgdXNlci5lbWFpbHNbMF0pIHtcbiAgICBlbWFpbCA9IHVzZXIuZW1haWxzWzBdLmFkZHJlc3M7XG4gIH1cblxuICAvLyBtYWtlIHN1cmUgd2UgaGF2ZSBhIHZhbGlkIGVtYWlsXG4gIGlmICghZW1haWwgfHxcbiAgICAhKHBsdWNrQWRkcmVzc2VzKHVzZXIuZW1haWxzKS5pbmNsdWRlcyhlbWFpbCkpKSB7XG4gICAgaGFuZGxlRXJyb3IoXCJObyBzdWNoIGVtYWlsIGZvciB1c2VyLlwiKTtcbiAgfVxuXG4gIGNvbnN0IHRva2VuID0gUmFuZG9tLnNlY3JldCgpO1xuICBjb25zdCB0b2tlblJlY29yZCA9IHtcbiAgICB0b2tlbixcbiAgICBlbWFpbCxcbiAgICB3aGVuOiBuZXcgRGF0ZSgpXG4gIH07XG5cbiAgaWYgKHJlYXNvbiA9PT0gJ3Jlc2V0UGFzc3dvcmQnKSB7XG4gICAgdG9rZW5SZWNvcmQucmVhc29uID0gJ3Jlc2V0JztcbiAgfSBlbHNlIGlmIChyZWFzb24gPT09ICdlbnJvbGxBY2NvdW50Jykge1xuICAgIHRva2VuUmVjb3JkLnJlYXNvbiA9ICdlbnJvbGwnO1xuICB9IGVsc2UgaWYgKHJlYXNvbikge1xuICAgIC8vIGZhbGxiYWNrIHNvIHRoYXQgdGhpcyBmdW5jdGlvbiBjYW4gYmUgdXNlZCBmb3IgdW5rbm93biByZWFzb25zIGFzIHdlbGxcbiAgICB0b2tlblJlY29yZC5yZWFzb24gPSByZWFzb247XG4gIH1cblxuICBpZiAoZXh0cmFUb2tlbkRhdGEpIHtcbiAgICBPYmplY3QuYXNzaWduKHRva2VuUmVjb3JkLCBleHRyYVRva2VuRGF0YSk7XG4gIH1cblxuICBNZXRlb3IudXNlcnMudXBkYXRlKHtfaWQ6IHVzZXIuX2lkfSwgeyRzZXQ6IHtcbiAgICAnc2VydmljZXMucGFzc3dvcmQucmVzZXQnOiB0b2tlblJlY29yZFxuICB9fSk7XG5cbiAgLy8gYmVmb3JlIHBhc3NpbmcgdG8gdGVtcGxhdGUsIHVwZGF0ZSB1c2VyIG9iamVjdCB3aXRoIG5ldyB0b2tlblxuICBNZXRlb3IuX2Vuc3VyZSh1c2VyLCAnc2VydmljZXMnLCAncGFzc3dvcmQnKS5yZXNldCA9IHRva2VuUmVjb3JkO1xuXG4gIHJldHVybiB7ZW1haWwsIHVzZXIsIHRva2VufTtcbn07XG5cbi8qKlxuICogQHN1bW1hcnkgR2VuZXJhdGVzIGFuIGUtbWFpbCB2ZXJpZmljYXRpb24gdG9rZW4gYW5kIHNhdmVzIGl0IGludG8gdGhlIGRhdGFiYXNlLlxuICogQGxvY3VzIFNlcnZlclxuICogQHBhcmFtIHtTdHJpbmd9IHVzZXJJZCBUaGUgaWQgb2YgdGhlIHVzZXIgdG8gZ2VuZXJhdGUgdGhlICBlLW1haWwgdmVyaWZpY2F0aW9uIHRva2VuIGZvci5cbiAqIEBwYXJhbSB7U3RyaW5nfSBlbWFpbCBXaGljaCBhZGRyZXNzIG9mIHRoZSB1c2VyIHRvIGdlbmVyYXRlIHRoZSBlLW1haWwgdmVyaWZpY2F0aW9uIHRva2VuIGZvci4gVGhpcyBhZGRyZXNzIG11c3QgYmUgaW4gdGhlIHVzZXIncyBgZW1haWxzYCBsaXN0LiBJZiBgbnVsbGAsIGRlZmF1bHRzIHRvIHRoZSBmaXJzdCB1bnZlcmlmaWVkIGVtYWlsIGluIHRoZSBsaXN0LlxuICogQHBhcmFtIHtPYmplY3R9IFtleHRyYVRva2VuRGF0YV0gT3B0aW9uYWwgYWRkaXRpb25hbCBkYXRhIHRvIGJlIGFkZGVkIGludG8gdGhlIHRva2VuIHJlY29yZC5cbiAqIEByZXR1cm5zIHtPYmplY3R9IE9iamVjdCB3aXRoIHtlbWFpbCwgdXNlciwgdG9rZW59IHZhbHVlcy5cbiAqIEBpbXBvcnRGcm9tUGFja2FnZSBhY2NvdW50cy1iYXNlXG4gKi9cbkFjY291bnRzLmdlbmVyYXRlVmVyaWZpY2F0aW9uVG9rZW4gPSAodXNlcklkLCBlbWFpbCwgZXh0cmFUb2tlbkRhdGEpID0+IHtcbiAgLy8gTWFrZSBzdXJlIHRoZSB1c2VyIGV4aXN0cywgYW5kIGVtYWlsIGlzIG9uZSBvZiB0aGVpciBhZGRyZXNzZXMuXG4gIC8vIERvbid0IGxpbWl0IHRoZSBmaWVsZHMgaW4gdGhlIHVzZXIgb2JqZWN0IHNpbmNlIHRoZSB1c2VyIGlzIHJldHVybmVkXG4gIC8vIGJ5IHRoZSBmdW5jdGlvbiBhbmQgc29tZSBvdGhlciBmaWVsZHMgbWlnaHQgYmUgdXNlZCBlbHNld2hlcmUuXG4gIGNvbnN0IHVzZXIgPSBnZXRVc2VyQnlJZCh1c2VySWQpO1xuICBpZiAoIXVzZXIpIHtcbiAgICBoYW5kbGVFcnJvcihcIkNhbid0IGZpbmQgdXNlclwiKTtcbiAgfVxuXG4gIC8vIHBpY2sgdGhlIGZpcnN0IHVudmVyaWZpZWQgZW1haWwgaWYgd2Ugd2VyZW4ndCBwYXNzZWQgYW4gZW1haWwuXG4gIGlmICghZW1haWwpIHtcbiAgICBjb25zdCBlbWFpbFJlY29yZCA9ICh1c2VyLmVtYWlscyB8fCBbXSkuZmluZChlID0+ICFlLnZlcmlmaWVkKTtcbiAgICBlbWFpbCA9IChlbWFpbFJlY29yZCB8fCB7fSkuYWRkcmVzcztcblxuICAgIGlmICghZW1haWwpIHtcbiAgICAgIGhhbmRsZUVycm9yKFwiVGhhdCB1c2VyIGhhcyBubyB1bnZlcmlmaWVkIGVtYWlsIGFkZHJlc3Nlcy5cIik7XG4gICAgfVxuICB9XG5cbiAgLy8gbWFrZSBzdXJlIHdlIGhhdmUgYSB2YWxpZCBlbWFpbFxuICBpZiAoIWVtYWlsIHx8XG4gICAgIShwbHVja0FkZHJlc3Nlcyh1c2VyLmVtYWlscykuaW5jbHVkZXMoZW1haWwpKSkge1xuICAgIGhhbmRsZUVycm9yKFwiTm8gc3VjaCBlbWFpbCBmb3IgdXNlci5cIik7XG4gIH1cblxuICBjb25zdCB0b2tlbiA9IFJhbmRvbS5zZWNyZXQoKTtcbiAgY29uc3QgdG9rZW5SZWNvcmQgPSB7XG4gICAgdG9rZW4sXG4gICAgLy8gVE9ETzogVGhpcyBzaG91bGQgcHJvYmFibHkgYmUgcmVuYW1lZCB0byBcImVtYWlsXCIgdG8gbWF0Y2ggcmVzZXQgdG9rZW4gcmVjb3JkLlxuICAgIGFkZHJlc3M6IGVtYWlsLFxuICAgIHdoZW46IG5ldyBEYXRlKClcbiAgfTtcblxuICBpZiAoZXh0cmFUb2tlbkRhdGEpIHtcbiAgICBPYmplY3QuYXNzaWduKHRva2VuUmVjb3JkLCBleHRyYVRva2VuRGF0YSk7XG4gIH1cblxuICBNZXRlb3IudXNlcnMudXBkYXRlKHtfaWQ6IHVzZXIuX2lkfSwgeyRwdXNoOiB7XG4gICAgJ3NlcnZpY2VzLmVtYWlsLnZlcmlmaWNhdGlvblRva2Vucyc6IHRva2VuUmVjb3JkXG4gIH19KTtcblxuICAvLyBiZWZvcmUgcGFzc2luZyB0byB0ZW1wbGF0ZSwgdXBkYXRlIHVzZXIgb2JqZWN0IHdpdGggbmV3IHRva2VuXG4gIE1ldGVvci5fZW5zdXJlKHVzZXIsICdzZXJ2aWNlcycsICdlbWFpbCcpO1xuICBpZiAoIXVzZXIuc2VydmljZXMuZW1haWwudmVyaWZpY2F0aW9uVG9rZW5zKSB7XG4gICAgdXNlci5zZXJ2aWNlcy5lbWFpbC52ZXJpZmljYXRpb25Ub2tlbnMgPSBbXTtcbiAgfVxuICB1c2VyLnNlcnZpY2VzLmVtYWlsLnZlcmlmaWNhdGlvblRva2Vucy5wdXNoKHRva2VuUmVjb3JkKTtcblxuICByZXR1cm4ge2VtYWlsLCB1c2VyLCB0b2tlbn07XG59O1xuXG4vKipcbiAqIEBzdW1tYXJ5IENyZWF0ZXMgb3B0aW9ucyBmb3IgZW1haWwgc2VuZGluZyBmb3IgcmVzZXQgcGFzc3dvcmQgYW5kIGVucm9sbCBhY2NvdW50IGVtYWlscy5cbiAqIFlvdSBjYW4gdXNlIHRoaXMgZnVuY3Rpb24gd2hlbiBjdXN0b21pemluZyBhIHJlc2V0IHBhc3N3b3JkIG9yIGVucm9sbCBhY2NvdW50IGVtYWlsIHNlbmRpbmcuXG4gKiBAbG9jdXMgU2VydmVyXG4gKiBAcGFyYW0ge09iamVjdH0gZW1haWwgV2hpY2ggYWRkcmVzcyBvZiB0aGUgdXNlcidzIHRvIHNlbmQgdGhlIGVtYWlsIHRvLlxuICogQHBhcmFtIHtPYmplY3R9IHVzZXIgVGhlIHVzZXIgb2JqZWN0IHRvIGdlbmVyYXRlIG9wdGlvbnMgZm9yLlxuICogQHBhcmFtIHtTdHJpbmd9IHVybCBVUkwgdG8gd2hpY2ggdXNlciBpcyBkaXJlY3RlZCB0byBjb25maXJtIHRoZSBlbWFpbC5cbiAqIEBwYXJhbSB7U3RyaW5nfSByZWFzb24gYHJlc2V0UGFzc3dvcmRgIG9yIGBlbnJvbGxBY2NvdW50YC5cbiAqIEByZXR1cm5zIHtPYmplY3R9IE9wdGlvbnMgd2hpY2ggY2FuIGJlIHBhc3NlZCB0byBgRW1haWwuc2VuZGAuXG4gKiBAaW1wb3J0RnJvbVBhY2thZ2UgYWNjb3VudHMtYmFzZVxuICovXG5BY2NvdW50cy5nZW5lcmF0ZU9wdGlvbnNGb3JFbWFpbCA9IChlbWFpbCwgdXNlciwgdXJsLCByZWFzb24pID0+IHtcbiAgY29uc3Qgb3B0aW9ucyA9IHtcbiAgICB0bzogZW1haWwsXG4gICAgZnJvbTogQWNjb3VudHMuZW1haWxUZW1wbGF0ZXNbcmVhc29uXS5mcm9tXG4gICAgICA/IEFjY291bnRzLmVtYWlsVGVtcGxhdGVzW3JlYXNvbl0uZnJvbSh1c2VyKVxuICAgICAgOiBBY2NvdW50cy5lbWFpbFRlbXBsYXRlcy5mcm9tLFxuICAgIHN1YmplY3Q6IEFjY291bnRzLmVtYWlsVGVtcGxhdGVzW3JlYXNvbl0uc3ViamVjdCh1c2VyKVxuICB9O1xuXG4gIGlmICh0eXBlb2YgQWNjb3VudHMuZW1haWxUZW1wbGF0ZXNbcmVhc29uXS50ZXh0ID09PSAnZnVuY3Rpb24nKSB7XG4gICAgb3B0aW9ucy50ZXh0ID0gQWNjb3VudHMuZW1haWxUZW1wbGF0ZXNbcmVhc29uXS50ZXh0KHVzZXIsIHVybCk7XG4gIH1cblxuICBpZiAodHlwZW9mIEFjY291bnRzLmVtYWlsVGVtcGxhdGVzW3JlYXNvbl0uaHRtbCA9PT0gJ2Z1bmN0aW9uJykge1xuICAgIG9wdGlvbnMuaHRtbCA9IEFjY291bnRzLmVtYWlsVGVtcGxhdGVzW3JlYXNvbl0uaHRtbCh1c2VyLCB1cmwpO1xuICB9XG5cbiAgaWYgKHR5cGVvZiBBY2NvdW50cy5lbWFpbFRlbXBsYXRlcy5oZWFkZXJzID09PSAnb2JqZWN0Jykge1xuICAgIG9wdGlvbnMuaGVhZGVycyA9IEFjY291bnRzLmVtYWlsVGVtcGxhdGVzLmhlYWRlcnM7XG4gIH1cblxuICByZXR1cm4gb3B0aW9ucztcbn07XG5cbi8vIHNlbmQgdGhlIHVzZXIgYW4gZW1haWwgd2l0aCBhIGxpbmsgdGhhdCB3aGVuIG9wZW5lZCBhbGxvd3MgdGhlIHVzZXJcbi8vIHRvIHNldCBhIG5ldyBwYXNzd29yZCwgd2l0aG91dCB0aGUgb2xkIHBhc3N3b3JkLlxuXG4vKipcbiAqIEBzdW1tYXJ5IFNlbmQgYW4gZW1haWwgd2l0aCBhIGxpbmsgdGhlIHVzZXIgY2FuIHVzZSB0byByZXNldCB0aGVpciBwYXNzd29yZC5cbiAqIEBsb2N1cyBTZXJ2ZXJcbiAqIEBwYXJhbSB7U3RyaW5nfSB1c2VySWQgVGhlIGlkIG9mIHRoZSB1c2VyIHRvIHNlbmQgZW1haWwgdG8uXG4gKiBAcGFyYW0ge1N0cmluZ30gW2VtYWlsXSBPcHRpb25hbC4gV2hpY2ggYWRkcmVzcyBvZiB0aGUgdXNlcidzIHRvIHNlbmQgdGhlIGVtYWlsIHRvLiBUaGlzIGFkZHJlc3MgbXVzdCBiZSBpbiB0aGUgdXNlcidzIGBlbWFpbHNgIGxpc3QuIERlZmF1bHRzIHRvIHRoZSBmaXJzdCBlbWFpbCBpbiB0aGUgbGlzdC5cbiAqIEBwYXJhbSB7T2JqZWN0fSBbZXh0cmFUb2tlbkRhdGFdIE9wdGlvbmFsIGFkZGl0aW9uYWwgZGF0YSB0byBiZSBhZGRlZCBpbnRvIHRoZSB0b2tlbiByZWNvcmQuXG4gKiBAcmV0dXJucyB7T2JqZWN0fSBPYmplY3Qgd2l0aCB7ZW1haWwsIHVzZXIsIHRva2VuLCB1cmwsIG9wdGlvbnN9IHZhbHVlcy5cbiAqIEBpbXBvcnRGcm9tUGFja2FnZSBhY2NvdW50cy1iYXNlXG4gKi9cbkFjY291bnRzLnNlbmRSZXNldFBhc3N3b3JkRW1haWwgPSAodXNlcklkLCBlbWFpbCwgZXh0cmFUb2tlbkRhdGEpID0+IHtcbiAgY29uc3Qge2VtYWlsOiByZWFsRW1haWwsIHVzZXIsIHRva2VufSA9XG4gICAgQWNjb3VudHMuZ2VuZXJhdGVSZXNldFRva2VuKHVzZXJJZCwgZW1haWwsICdyZXNldFBhc3N3b3JkJywgZXh0cmFUb2tlbkRhdGEpO1xuICBjb25zdCB1cmwgPSBBY2NvdW50cy51cmxzLnJlc2V0UGFzc3dvcmQodG9rZW4pO1xuICBjb25zdCBvcHRpb25zID0gQWNjb3VudHMuZ2VuZXJhdGVPcHRpb25zRm9yRW1haWwocmVhbEVtYWlsLCB1c2VyLCB1cmwsICdyZXNldFBhc3N3b3JkJyk7XG4gIEVtYWlsLnNlbmQob3B0aW9ucyk7XG4gIGlmIChNZXRlb3IuaXNEZXZlbG9wbWVudCkge1xuICAgIGNvbnNvbGUubG9nKGBcXG5SZXNldCBwYXNzd29yZCBVUkw6ICR7dXJsfWApO1xuICB9XG4gIHJldHVybiB7ZW1haWw6IHJlYWxFbWFpbCwgdXNlciwgdG9rZW4sIHVybCwgb3B0aW9uc307XG59O1xuXG4vLyBzZW5kIHRoZSB1c2VyIGFuIGVtYWlsIGluZm9ybWluZyB0aGVtIHRoYXQgdGhlaXIgYWNjb3VudCB3YXMgY3JlYXRlZCwgd2l0aFxuLy8gYSBsaW5rIHRoYXQgd2hlbiBvcGVuZWQgYm90aCBtYXJrcyB0aGVpciBlbWFpbCBhcyB2ZXJpZmllZCBhbmQgZm9yY2VzIHRoZW1cbi8vIHRvIGNob29zZSB0aGVpciBwYXNzd29yZC4gVGhlIGVtYWlsIG11c3QgYmUgb25lIG9mIHRoZSBhZGRyZXNzZXMgaW4gdGhlXG4vLyB1c2VyJ3MgZW1haWxzIGZpZWxkLCBvciB1bmRlZmluZWQgdG8gcGljayB0aGUgZmlyc3QgZW1haWwgYXV0b21hdGljYWxseS5cbi8vXG4vLyBUaGlzIGlzIG5vdCBjYWxsZWQgYXV0b21hdGljYWxseS4gSXQgbXVzdCBiZSBjYWxsZWQgbWFudWFsbHkgaWYgeW91XG4vLyB3YW50IHRvIHVzZSBlbnJvbGxtZW50IGVtYWlscy5cblxuLyoqXG4gKiBAc3VtbWFyeSBTZW5kIGFuIGVtYWlsIHdpdGggYSBsaW5rIHRoZSB1c2VyIGNhbiB1c2UgdG8gc2V0IHRoZWlyIGluaXRpYWwgcGFzc3dvcmQuXG4gKiBAbG9jdXMgU2VydmVyXG4gKiBAcGFyYW0ge1N0cmluZ30gdXNlcklkIFRoZSBpZCBvZiB0aGUgdXNlciB0byBzZW5kIGVtYWlsIHRvLlxuICogQHBhcmFtIHtTdHJpbmd9IFtlbWFpbF0gT3B0aW9uYWwuIFdoaWNoIGFkZHJlc3Mgb2YgdGhlIHVzZXIncyB0byBzZW5kIHRoZSBlbWFpbCB0by4gVGhpcyBhZGRyZXNzIG11c3QgYmUgaW4gdGhlIHVzZXIncyBgZW1haWxzYCBsaXN0LiBEZWZhdWx0cyB0byB0aGUgZmlyc3QgZW1haWwgaW4gdGhlIGxpc3QuXG4gKiBAcGFyYW0ge09iamVjdH0gW2V4dHJhVG9rZW5EYXRhXSBPcHRpb25hbCBhZGRpdGlvbmFsIGRhdGEgdG8gYmUgYWRkZWQgaW50byB0aGUgdG9rZW4gcmVjb3JkLlxuICogQHJldHVybnMge09iamVjdH0gT2JqZWN0IHdpdGgge2VtYWlsLCB1c2VyLCB0b2tlbiwgdXJsLCBvcHRpb25zfSB2YWx1ZXMuXG4gKiBAaW1wb3J0RnJvbVBhY2thZ2UgYWNjb3VudHMtYmFzZVxuICovXG5BY2NvdW50cy5zZW5kRW5yb2xsbWVudEVtYWlsID0gKHVzZXJJZCwgZW1haWwsIGV4dHJhVG9rZW5EYXRhKSA9PiB7XG4gIGNvbnN0IHtlbWFpbDogcmVhbEVtYWlsLCB1c2VyLCB0b2tlbn0gPVxuICAgIEFjY291bnRzLmdlbmVyYXRlUmVzZXRUb2tlbih1c2VySWQsIGVtYWlsLCAnZW5yb2xsQWNjb3VudCcsIGV4dHJhVG9rZW5EYXRhKTtcbiAgY29uc3QgdXJsID0gQWNjb3VudHMudXJscy5lbnJvbGxBY2NvdW50KHRva2VuKTtcbiAgY29uc3Qgb3B0aW9ucyA9IEFjY291bnRzLmdlbmVyYXRlT3B0aW9uc0ZvckVtYWlsKHJlYWxFbWFpbCwgdXNlciwgdXJsLCAnZW5yb2xsQWNjb3VudCcpO1xuICBFbWFpbC5zZW5kKG9wdGlvbnMpO1xuICBpZiAoTWV0ZW9yLmlzRGV2ZWxvcG1lbnQpIHtcbiAgICBjb25zb2xlLmxvZyhgXFxuRW5yb2xsbWVudCBlbWFpbCBVUkw6ICR7dXJsfWApO1xuICB9XG4gIHJldHVybiB7ZW1haWw6IHJlYWxFbWFpbCwgdXNlciwgdG9rZW4sIHVybCwgb3B0aW9uc307XG59O1xuXG5cbi8vIFRha2UgdG9rZW4gZnJvbSBzZW5kUmVzZXRQYXNzd29yZEVtYWlsIG9yIHNlbmRFbnJvbGxtZW50RW1haWwsIGNoYW5nZVxuLy8gdGhlIHVzZXJzIHBhc3N3b3JkLCBhbmQgbG9nIHRoZW0gaW4uXG5NZXRlb3IubWV0aG9kcyh7cmVzZXRQYXNzd29yZDogZnVuY3Rpb24gKC4uLmFyZ3MpIHtcbiAgY29uc3QgdG9rZW4gPSBhcmdzWzBdO1xuICBjb25zdCBuZXdQYXNzd29yZCA9IGFyZ3NbMV07XG4gIHJldHVybiBBY2NvdW50cy5fbG9naW5NZXRob2QoXG4gICAgdGhpcyxcbiAgICBcInJlc2V0UGFzc3dvcmRcIixcbiAgICBhcmdzLFxuICAgIFwicGFzc3dvcmRcIixcbiAgICAoKSA9PiB7XG4gICAgICBjaGVjayh0b2tlbiwgU3RyaW5nKTtcbiAgICAgIGNoZWNrKG5ld1Bhc3N3b3JkLCBwYXNzd29yZFZhbGlkYXRvcik7XG5cbiAgICAgIGNvbnN0IHVzZXIgPSBNZXRlb3IudXNlcnMuZmluZE9uZShcbiAgICAgICAge1wic2VydmljZXMucGFzc3dvcmQucmVzZXQudG9rZW5cIjogdG9rZW59LFxuICAgICAgICB7ZmllbGRzOiB7XG4gICAgICAgICAgc2VydmljZXM6IDEsXG4gICAgICAgICAgZW1haWxzOiAxLFxuICAgICAgICB9fVxuICAgICAgKTtcbiAgICAgIGlmICghdXNlcikge1xuICAgICAgICB0aHJvdyBuZXcgTWV0ZW9yLkVycm9yKDQwMywgXCJUb2tlbiBleHBpcmVkXCIpO1xuICAgICAgfVxuICAgICAgY29uc3QgeyB3aGVuLCByZWFzb24sIGVtYWlsIH0gPSB1c2VyLnNlcnZpY2VzLnBhc3N3b3JkLnJlc2V0O1xuICAgICAgbGV0IHRva2VuTGlmZXRpbWVNcyA9IEFjY291bnRzLl9nZXRQYXNzd29yZFJlc2V0VG9rZW5MaWZldGltZU1zKCk7XG4gICAgICBpZiAocmVhc29uID09PSBcImVucm9sbFwiKSB7XG4gICAgICAgIHRva2VuTGlmZXRpbWVNcyA9IEFjY291bnRzLl9nZXRQYXNzd29yZEVucm9sbFRva2VuTGlmZXRpbWVNcygpO1xuICAgICAgfVxuICAgICAgY29uc3QgY3VycmVudFRpbWVNcyA9IERhdGUubm93KCk7XG4gICAgICBpZiAoKGN1cnJlbnRUaW1lTXMgLSB3aGVuKSA+IHRva2VuTGlmZXRpbWVNcylcbiAgICAgICAgdGhyb3cgbmV3IE1ldGVvci5FcnJvcig0MDMsIFwiVG9rZW4gZXhwaXJlZFwiKTtcbiAgICAgIGlmICghKHBsdWNrQWRkcmVzc2VzKHVzZXIuZW1haWxzKS5pbmNsdWRlcyhlbWFpbCkpKVxuICAgICAgICByZXR1cm4ge1xuICAgICAgICAgIHVzZXJJZDogdXNlci5faWQsXG4gICAgICAgICAgZXJyb3I6IG5ldyBNZXRlb3IuRXJyb3IoNDAzLCBcIlRva2VuIGhhcyBpbnZhbGlkIGVtYWlsIGFkZHJlc3NcIilcbiAgICAgICAgfTtcblxuICAgICAgY29uc3QgaGFzaGVkID0gaGFzaFBhc3N3b3JkKG5ld1Bhc3N3b3JkKTtcblxuICAgICAgLy8gTk9URTogV2UncmUgYWJvdXQgdG8gaW52YWxpZGF0ZSB0b2tlbnMgb24gdGhlIHVzZXIsIHdobyB3ZSBtaWdodCBiZVxuICAgICAgLy8gbG9nZ2VkIGluIGFzLiBNYWtlIHN1cmUgdG8gYXZvaWQgbG9nZ2luZyBvdXJzZWx2ZXMgb3V0IGlmIHRoaXNcbiAgICAgIC8vIGhhcHBlbnMuIEJ1dCBhbHNvIG1ha2Ugc3VyZSBub3QgdG8gbGVhdmUgdGhlIGNvbm5lY3Rpb24gaW4gYSBzdGF0ZVxuICAgICAgLy8gb2YgaGF2aW5nIGEgYmFkIHRva2VuIHNldCBpZiB0aGluZ3MgZmFpbC5cbiAgICAgIGNvbnN0IG9sZFRva2VuID0gQWNjb3VudHMuX2dldExvZ2luVG9rZW4odGhpcy5jb25uZWN0aW9uLmlkKTtcbiAgICAgIEFjY291bnRzLl9zZXRMb2dpblRva2VuKHVzZXIuX2lkLCB0aGlzLmNvbm5lY3Rpb24sIG51bGwpO1xuICAgICAgY29uc3QgcmVzZXRUb09sZFRva2VuID0gKCkgPT5cbiAgICAgICAgQWNjb3VudHMuX3NldExvZ2luVG9rZW4odXNlci5faWQsIHRoaXMuY29ubmVjdGlvbiwgb2xkVG9rZW4pO1xuXG4gICAgICB0cnkge1xuICAgICAgICAvLyBVcGRhdGUgdGhlIHVzZXIgcmVjb3JkIGJ5OlxuICAgICAgICAvLyAtIENoYW5naW5nIHRoZSBwYXNzd29yZCB0byB0aGUgbmV3IG9uZVxuICAgICAgICAvLyAtIEZvcmdldHRpbmcgYWJvdXQgdGhlIHJlc2V0IHRva2VuIHRoYXQgd2FzIGp1c3QgdXNlZFxuICAgICAgICAvLyAtIFZlcmlmeWluZyB0aGVpciBlbWFpbCwgc2luY2UgdGhleSBnb3QgdGhlIHBhc3N3b3JkIHJlc2V0IHZpYSBlbWFpbC5cbiAgICAgICAgY29uc3QgYWZmZWN0ZWRSZWNvcmRzID0gTWV0ZW9yLnVzZXJzLnVwZGF0ZShcbiAgICAgICAgICB7XG4gICAgICAgICAgICBfaWQ6IHVzZXIuX2lkLFxuICAgICAgICAgICAgJ2VtYWlscy5hZGRyZXNzJzogZW1haWwsXG4gICAgICAgICAgICAnc2VydmljZXMucGFzc3dvcmQucmVzZXQudG9rZW4nOiB0b2tlblxuICAgICAgICAgIH0sXG4gICAgICAgICAgeyRzZXQ6IHsnc2VydmljZXMucGFzc3dvcmQuYmNyeXB0JzogaGFzaGVkLFxuICAgICAgICAgICAgICAgICAgJ2VtYWlscy4kLnZlcmlmaWVkJzogdHJ1ZX0sXG4gICAgICAgICAgICR1bnNldDogeydzZXJ2aWNlcy5wYXNzd29yZC5yZXNldCc6IDEsXG4gICAgICAgICAgICAgICAgICAgICdzZXJ2aWNlcy5wYXNzd29yZC5zcnAnOiAxfX0pO1xuICAgICAgICBpZiAoYWZmZWN0ZWRSZWNvcmRzICE9PSAxKVxuICAgICAgICAgIHJldHVybiB7XG4gICAgICAgICAgICB1c2VySWQ6IHVzZXIuX2lkLFxuICAgICAgICAgICAgZXJyb3I6IG5ldyBNZXRlb3IuRXJyb3IoNDAzLCBcIkludmFsaWQgZW1haWxcIilcbiAgICAgICAgICB9O1xuICAgICAgfSBjYXRjaCAoZXJyKSB7XG4gICAgICAgIHJlc2V0VG9PbGRUb2tlbigpO1xuICAgICAgICB0aHJvdyBlcnI7XG4gICAgICB9XG5cbiAgICAgIC8vIFJlcGxhY2UgYWxsIHZhbGlkIGxvZ2luIHRva2VucyB3aXRoIG5ldyBvbmVzIChjaGFuZ2luZ1xuICAgICAgLy8gcGFzc3dvcmQgc2hvdWxkIGludmFsaWRhdGUgZXhpc3Rpbmcgc2Vzc2lvbnMpLlxuICAgICAgQWNjb3VudHMuX2NsZWFyQWxsTG9naW5Ub2tlbnModXNlci5faWQpO1xuXG4gICAgICByZXR1cm4ge3VzZXJJZDogdXNlci5faWR9O1xuICAgIH1cbiAgKTtcbn19KTtcblxuLy8vXG4vLy8gRU1BSUwgVkVSSUZJQ0FUSU9OXG4vLy9cblxuXG4vLyBzZW5kIHRoZSB1c2VyIGFuIGVtYWlsIHdpdGggYSBsaW5rIHRoYXQgd2hlbiBvcGVuZWQgbWFya3MgdGhhdFxuLy8gYWRkcmVzcyBhcyB2ZXJpZmllZFxuXG4vKipcbiAqIEBzdW1tYXJ5IFNlbmQgYW4gZW1haWwgd2l0aCBhIGxpbmsgdGhlIHVzZXIgY2FuIHVzZSB2ZXJpZnkgdGhlaXIgZW1haWwgYWRkcmVzcy5cbiAqIEBsb2N1cyBTZXJ2ZXJcbiAqIEBwYXJhbSB7U3RyaW5nfSB1c2VySWQgVGhlIGlkIG9mIHRoZSB1c2VyIHRvIHNlbmQgZW1haWwgdG8uXG4gKiBAcGFyYW0ge1N0cmluZ30gW2VtYWlsXSBPcHRpb25hbC4gV2hpY2ggYWRkcmVzcyBvZiB0aGUgdXNlcidzIHRvIHNlbmQgdGhlIGVtYWlsIHRvLiBUaGlzIGFkZHJlc3MgbXVzdCBiZSBpbiB0aGUgdXNlcidzIGBlbWFpbHNgIGxpc3QuIERlZmF1bHRzIHRvIHRoZSBmaXJzdCB1bnZlcmlmaWVkIGVtYWlsIGluIHRoZSBsaXN0LlxuICogQHBhcmFtIHtPYmplY3R9IFtleHRyYVRva2VuRGF0YV0gT3B0aW9uYWwgYWRkaXRpb25hbCBkYXRhIHRvIGJlIGFkZGVkIGludG8gdGhlIHRva2VuIHJlY29yZC5cbiAqIEByZXR1cm5zIHtPYmplY3R9IE9iamVjdCB3aXRoIHtlbWFpbCwgdXNlciwgdG9rZW4sIHVybCwgb3B0aW9uc30gdmFsdWVzLlxuICogQGltcG9ydEZyb21QYWNrYWdlIGFjY291bnRzLWJhc2VcbiAqL1xuQWNjb3VudHMuc2VuZFZlcmlmaWNhdGlvbkVtYWlsID0gKHVzZXJJZCwgZW1haWwsIGV4dHJhVG9rZW5EYXRhKSA9PiB7XG4gIC8vIFhYWCBBbHNvIGdlbmVyYXRlIGEgbGluayB1c2luZyB3aGljaCBzb21lb25lIGNhbiBkZWxldGUgdGhpc1xuICAvLyBhY2NvdW50IGlmIHRoZXkgb3duIHNhaWQgYWRkcmVzcyBidXQgd2VyZW4ndCB0aG9zZSB3aG8gY3JlYXRlZFxuICAvLyB0aGlzIGFjY291bnQuXG5cbiAgY29uc3Qge2VtYWlsOiByZWFsRW1haWwsIHVzZXIsIHRva2VufSA9XG4gICAgQWNjb3VudHMuZ2VuZXJhdGVWZXJpZmljYXRpb25Ub2tlbih1c2VySWQsIGVtYWlsLCBleHRyYVRva2VuRGF0YSk7XG4gIGNvbnN0IHVybCA9IEFjY291bnRzLnVybHMudmVyaWZ5RW1haWwodG9rZW4pO1xuICBjb25zdCBvcHRpb25zID0gQWNjb3VudHMuZ2VuZXJhdGVPcHRpb25zRm9yRW1haWwocmVhbEVtYWlsLCB1c2VyLCB1cmwsICd2ZXJpZnlFbWFpbCcpO1xuICBFbWFpbC5zZW5kKG9wdGlvbnMpO1xuICBpZiAoTWV0ZW9yLmlzRGV2ZWxvcG1lbnQpIHtcbiAgICBjb25zb2xlLmxvZyhgXFxuVmVyaWZpY2F0aW9uIGVtYWlsIFVSTDogJHt1cmx9YCk7XG4gIH1cbiAgcmV0dXJuIHtlbWFpbDogcmVhbEVtYWlsLCB1c2VyLCB0b2tlbiwgdXJsLCBvcHRpb25zfTtcbn07XG5cbi8vIFRha2UgdG9rZW4gZnJvbSBzZW5kVmVyaWZpY2F0aW9uRW1haWwsIG1hcmsgdGhlIGVtYWlsIGFzIHZlcmlmaWVkLFxuLy8gYW5kIGxvZyB0aGVtIGluLlxuTWV0ZW9yLm1ldGhvZHMoe3ZlcmlmeUVtYWlsOiBmdW5jdGlvbiAoLi4uYXJncykge1xuICBjb25zdCB0b2tlbiA9IGFyZ3NbMF07XG4gIHJldHVybiBBY2NvdW50cy5fbG9naW5NZXRob2QoXG4gICAgdGhpcyxcbiAgICBcInZlcmlmeUVtYWlsXCIsXG4gICAgYXJncyxcbiAgICBcInBhc3N3b3JkXCIsXG4gICAgKCkgPT4ge1xuICAgICAgY2hlY2sodG9rZW4sIFN0cmluZyk7XG5cbiAgICAgIGNvbnN0IHVzZXIgPSBNZXRlb3IudXNlcnMuZmluZE9uZShcbiAgICAgICAgeydzZXJ2aWNlcy5lbWFpbC52ZXJpZmljYXRpb25Ub2tlbnMudG9rZW4nOiB0b2tlbn0sXG4gICAgICAgIHtmaWVsZHM6IHtcbiAgICAgICAgICBzZXJ2aWNlczogMSxcbiAgICAgICAgICBlbWFpbHM6IDEsXG4gICAgICAgIH19XG4gICAgICApO1xuICAgICAgaWYgKCF1c2VyKVxuICAgICAgICB0aHJvdyBuZXcgTWV0ZW9yLkVycm9yKDQwMywgXCJWZXJpZnkgZW1haWwgbGluayBleHBpcmVkXCIpO1xuXG4gICAgICAgIGNvbnN0IHRva2VuUmVjb3JkID0gdXNlci5zZXJ2aWNlcy5lbWFpbC52ZXJpZmljYXRpb25Ub2tlbnMuZmluZChcbiAgICAgICAgICB0ID0+IHQudG9rZW4gPT0gdG9rZW5cbiAgICAgICAgKTtcbiAgICAgIGlmICghdG9rZW5SZWNvcmQpXG4gICAgICAgIHJldHVybiB7XG4gICAgICAgICAgdXNlcklkOiB1c2VyLl9pZCxcbiAgICAgICAgICBlcnJvcjogbmV3IE1ldGVvci5FcnJvcig0MDMsIFwiVmVyaWZ5IGVtYWlsIGxpbmsgZXhwaXJlZFwiKVxuICAgICAgICB9O1xuXG4gICAgICBjb25zdCBlbWFpbHNSZWNvcmQgPSB1c2VyLmVtYWlscy5maW5kKFxuICAgICAgICBlID0+IGUuYWRkcmVzcyA9PSB0b2tlblJlY29yZC5hZGRyZXNzXG4gICAgICApO1xuICAgICAgaWYgKCFlbWFpbHNSZWNvcmQpXG4gICAgICAgIHJldHVybiB7XG4gICAgICAgICAgdXNlcklkOiB1c2VyLl9pZCxcbiAgICAgICAgICBlcnJvcjogbmV3IE1ldGVvci5FcnJvcig0MDMsIFwiVmVyaWZ5IGVtYWlsIGxpbmsgaXMgZm9yIHVua25vd24gYWRkcmVzc1wiKVxuICAgICAgICB9O1xuXG4gICAgICAvLyBCeSBpbmNsdWRpbmcgdGhlIGFkZHJlc3MgaW4gdGhlIHF1ZXJ5LCB3ZSBjYW4gdXNlICdlbWFpbHMuJCcgaW4gdGhlXG4gICAgICAvLyBtb2RpZmllciB0byBnZXQgYSByZWZlcmVuY2UgdG8gdGhlIHNwZWNpZmljIG9iamVjdCBpbiB0aGUgZW1haWxzXG4gICAgICAvLyBhcnJheS4gU2VlXG4gICAgICAvLyBodHRwOi8vd3d3Lm1vbmdvZGIub3JnL2Rpc3BsYXkvRE9DUy9VcGRhdGluZy8jVXBkYXRpbmctVGhlJTI0cG9zaXRpb25hbG9wZXJhdG9yKVxuICAgICAgLy8gaHR0cDovL3d3dy5tb25nb2RiLm9yZy9kaXNwbGF5L0RPQ1MvVXBkYXRpbmcjVXBkYXRpbmctJTI0cHVsbFxuICAgICAgTWV0ZW9yLnVzZXJzLnVwZGF0ZShcbiAgICAgICAge19pZDogdXNlci5faWQsXG4gICAgICAgICAnZW1haWxzLmFkZHJlc3MnOiB0b2tlblJlY29yZC5hZGRyZXNzfSxcbiAgICAgICAgeyRzZXQ6IHsnZW1haWxzLiQudmVyaWZpZWQnOiB0cnVlfSxcbiAgICAgICAgICRwdWxsOiB7J3NlcnZpY2VzLmVtYWlsLnZlcmlmaWNhdGlvblRva2Vucyc6IHthZGRyZXNzOiB0b2tlblJlY29yZC5hZGRyZXNzfX19KTtcblxuICAgICAgcmV0dXJuIHt1c2VySWQ6IHVzZXIuX2lkfTtcbiAgICB9XG4gICk7XG59fSk7XG5cbi8qKlxuICogQHN1bW1hcnkgQWRkIGFuIGVtYWlsIGFkZHJlc3MgZm9yIGEgdXNlci4gVXNlIHRoaXMgaW5zdGVhZCBvZiBkaXJlY3RseVxuICogdXBkYXRpbmcgdGhlIGRhdGFiYXNlLiBUaGUgb3BlcmF0aW9uIHdpbGwgZmFpbCBpZiB0aGVyZSBpcyBhIGRpZmZlcmVudCB1c2VyXG4gKiB3aXRoIGFuIGVtYWlsIG9ubHkgZGlmZmVyaW5nIGluIGNhc2UuIElmIHRoZSBzcGVjaWZpZWQgdXNlciBoYXMgYW4gZXhpc3RpbmdcbiAqIGVtYWlsIG9ubHkgZGlmZmVyaW5nIGluIGNhc2UgaG93ZXZlciwgd2UgcmVwbGFjZSBpdC5cbiAqIEBsb2N1cyBTZXJ2ZXJcbiAqIEBwYXJhbSB7U3RyaW5nfSB1c2VySWQgVGhlIElEIG9mIHRoZSB1c2VyIHRvIHVwZGF0ZS5cbiAqIEBwYXJhbSB7U3RyaW5nfSBuZXdFbWFpbCBBIG5ldyBlbWFpbCBhZGRyZXNzIGZvciB0aGUgdXNlci5cbiAqIEBwYXJhbSB7Qm9vbGVhbn0gW3ZlcmlmaWVkXSBPcHRpb25hbCAtIHdoZXRoZXIgdGhlIG5ldyBlbWFpbCBhZGRyZXNzIHNob3VsZFxuICogYmUgbWFya2VkIGFzIHZlcmlmaWVkLiBEZWZhdWx0cyB0byBmYWxzZS5cbiAqIEBpbXBvcnRGcm9tUGFja2FnZSBhY2NvdW50cy1iYXNlXG4gKi9cbkFjY291bnRzLmFkZEVtYWlsID0gKHVzZXJJZCwgbmV3RW1haWwsIHZlcmlmaWVkKSA9PiB7XG4gIGNoZWNrKHVzZXJJZCwgTm9uRW1wdHlTdHJpbmcpO1xuICBjaGVjayhuZXdFbWFpbCwgTm9uRW1wdHlTdHJpbmcpO1xuICBjaGVjayh2ZXJpZmllZCwgTWF0Y2guT3B0aW9uYWwoQm9vbGVhbikpO1xuXG4gIGlmICh2ZXJpZmllZCA9PT0gdm9pZCAwKSB7XG4gICAgdmVyaWZpZWQgPSBmYWxzZTtcbiAgfVxuXG4gIGNvbnN0IHVzZXIgPSBnZXRVc2VyQnlJZCh1c2VySWQsIHtmaWVsZHM6IHtlbWFpbHM6IDF9fSk7XG4gIGlmICghdXNlcilcbiAgICB0aHJvdyBuZXcgTWV0ZW9yLkVycm9yKDQwMywgXCJVc2VyIG5vdCBmb3VuZFwiKTtcblxuICAvLyBBbGxvdyB1c2VycyB0byBjaGFuZ2UgdGhlaXIgb3duIGVtYWlsIHRvIGEgdmVyc2lvbiB3aXRoIGEgZGlmZmVyZW50IGNhc2VcblxuICAvLyBXZSBkb24ndCBoYXZlIHRvIGNhbGwgY2hlY2tGb3JDYXNlSW5zZW5zaXRpdmVEdXBsaWNhdGVzIHRvIGRvIGEgY2FzZVxuICAvLyBpbnNlbnNpdGl2ZSBjaGVjayBhY3Jvc3MgYWxsIGVtYWlscyBpbiB0aGUgZGF0YWJhc2UgaGVyZSBiZWNhdXNlOiAoMSkgaWZcbiAgLy8gdGhlcmUgaXMgbm8gY2FzZS1pbnNlbnNpdGl2ZSBkdXBsaWNhdGUgYmV0d2VlbiB0aGlzIHVzZXIgYW5kIG90aGVyIHVzZXJzLFxuICAvLyB0aGVuIHdlIGFyZSBPSyBhbmQgKDIpIGlmIHRoaXMgd291bGQgY3JlYXRlIGEgY29uZmxpY3Qgd2l0aCBvdGhlciB1c2Vyc1xuICAvLyB0aGVuIHRoZXJlIHdvdWxkIGFscmVhZHkgYmUgYSBjYXNlLWluc2Vuc2l0aXZlIGR1cGxpY2F0ZSBhbmQgd2UgY2FuJ3QgZml4XG4gIC8vIHRoYXQgaW4gdGhpcyBjb2RlIGFueXdheS5cbiAgY29uc3QgY2FzZUluc2Vuc2l0aXZlUmVnRXhwID1cbiAgICBuZXcgUmVnRXhwKGBeJHtNZXRlb3IuX2VzY2FwZVJlZ0V4cChuZXdFbWFpbCl9JGAsICdpJyk7XG5cbiAgY29uc3QgZGlkVXBkYXRlT3duRW1haWwgPSAodXNlci5lbWFpbHMgfHwgW10pLnJlZHVjZShcbiAgICAocHJldiwgZW1haWwpID0+IHtcbiAgICAgIGlmIChjYXNlSW5zZW5zaXRpdmVSZWdFeHAudGVzdChlbWFpbC5hZGRyZXNzKSkge1xuICAgICAgICBNZXRlb3IudXNlcnMudXBkYXRlKHtcbiAgICAgICAgICBfaWQ6IHVzZXIuX2lkLFxuICAgICAgICAgICdlbWFpbHMuYWRkcmVzcyc6IGVtYWlsLmFkZHJlc3NcbiAgICAgICAgfSwgeyRzZXQ6IHtcbiAgICAgICAgICAnZW1haWxzLiQuYWRkcmVzcyc6IG5ld0VtYWlsLFxuICAgICAgICAgICdlbWFpbHMuJC52ZXJpZmllZCc6IHZlcmlmaWVkXG4gICAgICAgIH19KTtcbiAgICAgICAgcmV0dXJuIHRydWU7XG4gICAgICB9IGVsc2Uge1xuICAgICAgICByZXR1cm4gcHJldjtcbiAgICAgIH1cbiAgICB9LFxuICAgIGZhbHNlXG4gICk7XG5cbiAgLy8gSW4gdGhlIG90aGVyIHVwZGF0ZXMgYmVsb3csIHdlIGhhdmUgdG8gZG8gYW5vdGhlciBjYWxsIHRvXG4gIC8vIGNoZWNrRm9yQ2FzZUluc2Vuc2l0aXZlRHVwbGljYXRlcyB0byBtYWtlIHN1cmUgdGhhdCBubyBjb25mbGljdGluZyB2YWx1ZXNcbiAgLy8gd2VyZSBhZGRlZCB0byB0aGUgZGF0YWJhc2UgaW4gdGhlIG1lYW50aW1lLiBXZSBkb24ndCBoYXZlIHRvIGRvIHRoaXMgZm9yXG4gIC8vIHRoZSBjYXNlIHdoZXJlIHRoZSB1c2VyIGlzIHVwZGF0aW5nIHRoZWlyIGVtYWlsIGFkZHJlc3MgdG8gb25lIHRoYXQgaXMgdGhlXG4gIC8vIHNhbWUgYXMgYmVmb3JlLCBidXQgb25seSBkaWZmZXJlbnQgYmVjYXVzZSBvZiBjYXBpdGFsaXphdGlvbi4gUmVhZCB0aGVcbiAgLy8gYmlnIGNvbW1lbnQgYWJvdmUgdG8gdW5kZXJzdGFuZCB3aHkuXG5cbiAgaWYgKGRpZFVwZGF0ZU93bkVtYWlsKSB7XG4gICAgcmV0dXJuO1xuICB9XG5cbiAgLy8gUGVyZm9ybSBhIGNhc2UgaW5zZW5zaXRpdmUgY2hlY2sgZm9yIGR1cGxpY2F0ZXMgYmVmb3JlIHVwZGF0ZVxuICBjaGVja0ZvckNhc2VJbnNlbnNpdGl2ZUR1cGxpY2F0ZXMoJ2VtYWlscy5hZGRyZXNzJywgJ0VtYWlsJywgbmV3RW1haWwsIHVzZXIuX2lkKTtcblxuICBNZXRlb3IudXNlcnMudXBkYXRlKHtcbiAgICBfaWQ6IHVzZXIuX2lkXG4gIH0sIHtcbiAgICAkYWRkVG9TZXQ6IHtcbiAgICAgIGVtYWlsczoge1xuICAgICAgICBhZGRyZXNzOiBuZXdFbWFpbCxcbiAgICAgICAgdmVyaWZpZWQ6IHZlcmlmaWVkXG4gICAgICB9XG4gICAgfVxuICB9KTtcblxuICAvLyBQZXJmb3JtIGFub3RoZXIgY2hlY2sgYWZ0ZXIgdXBkYXRlLCBpbiBjYXNlIGEgbWF0Y2hpbmcgdXNlciBoYXMgYmVlblxuICAvLyBpbnNlcnRlZCBpbiB0aGUgbWVhbnRpbWVcbiAgdHJ5IHtcbiAgICBjaGVja0ZvckNhc2VJbnNlbnNpdGl2ZUR1cGxpY2F0ZXMoJ2VtYWlscy5hZGRyZXNzJywgJ0VtYWlsJywgbmV3RW1haWwsIHVzZXIuX2lkKTtcbiAgfSBjYXRjaCAoZXgpIHtcbiAgICAvLyBVbmRvIHVwZGF0ZSBpZiB0aGUgY2hlY2sgZmFpbHNcbiAgICBNZXRlb3IudXNlcnMudXBkYXRlKHtfaWQ6IHVzZXIuX2lkfSxcbiAgICAgIHskcHVsbDoge2VtYWlsczoge2FkZHJlc3M6IG5ld0VtYWlsfX19KTtcbiAgICB0aHJvdyBleDtcbiAgfVxufVxuXG4vKipcbiAqIEBzdW1tYXJ5IFJlbW92ZSBhbiBlbWFpbCBhZGRyZXNzIGZvciBhIHVzZXIuIFVzZSB0aGlzIGluc3RlYWQgb2YgdXBkYXRpbmdcbiAqIHRoZSBkYXRhYmFzZSBkaXJlY3RseS5cbiAqIEBsb2N1cyBTZXJ2ZXJcbiAqIEBwYXJhbSB7U3RyaW5nfSB1c2VySWQgVGhlIElEIG9mIHRoZSB1c2VyIHRvIHVwZGF0ZS5cbiAqIEBwYXJhbSB7U3RyaW5nfSBlbWFpbCBUaGUgZW1haWwgYWRkcmVzcyB0byByZW1vdmUuXG4gKiBAaW1wb3J0RnJvbVBhY2thZ2UgYWNjb3VudHMtYmFzZVxuICovXG5BY2NvdW50cy5yZW1vdmVFbWFpbCA9ICh1c2VySWQsIGVtYWlsKSA9PiB7XG4gIGNoZWNrKHVzZXJJZCwgTm9uRW1wdHlTdHJpbmcpO1xuICBjaGVjayhlbWFpbCwgTm9uRW1wdHlTdHJpbmcpO1xuXG4gIGNvbnN0IHVzZXIgPSBnZXRVc2VyQnlJZCh1c2VySWQsIHtmaWVsZHM6IHtfaWQ6IDF9fSk7XG4gIGlmICghdXNlcilcbiAgICB0aHJvdyBuZXcgTWV0ZW9yLkVycm9yKDQwMywgXCJVc2VyIG5vdCBmb3VuZFwiKTtcblxuICBNZXRlb3IudXNlcnMudXBkYXRlKHtfaWQ6IHVzZXIuX2lkfSxcbiAgICB7JHB1bGw6IHtlbWFpbHM6IHthZGRyZXNzOiBlbWFpbH19fSk7XG59XG5cbi8vL1xuLy8vIENSRUFUSU5HIFVTRVJTXG4vLy9cblxuLy8gU2hhcmVkIGNyZWF0ZVVzZXIgZnVuY3Rpb24gY2FsbGVkIGZyb20gdGhlIGNyZWF0ZVVzZXIgbWV0aG9kLCBib3RoXG4vLyBpZiBvcmlnaW5hdGVzIGluIGNsaWVudCBvciBzZXJ2ZXIgY29kZS4gQ2FsbHMgdXNlciBwcm92aWRlZCBob29rcyxcbi8vIGRvZXMgdGhlIGFjdHVhbCB1c2VyIGluc2VydGlvbi5cbi8vXG4vLyByZXR1cm5zIHRoZSB1c2VyIGlkXG5jb25zdCBjcmVhdGVVc2VyID0gb3B0aW9ucyA9PiB7XG4gIC8vIFVua25vd24ga2V5cyBhbGxvd2VkLCBiZWNhdXNlIGEgb25DcmVhdGVVc2VySG9vayBjYW4gdGFrZSBhcmJpdHJhcnlcbiAgLy8gb3B0aW9ucy5cbiAgY2hlY2sob3B0aW9ucywgTWF0Y2guT2JqZWN0SW5jbHVkaW5nKHtcbiAgICB1c2VybmFtZTogTWF0Y2guT3B0aW9uYWwoU3RyaW5nKSxcbiAgICBlbWFpbDogTWF0Y2guT3B0aW9uYWwoU3RyaW5nKSxcbiAgICBwYXNzd29yZDogTWF0Y2guT3B0aW9uYWwocGFzc3dvcmRWYWxpZGF0b3IpXG4gIH0pKTtcblxuICBjb25zdCB7IHVzZXJuYW1lLCBlbWFpbCwgcGFzc3dvcmQgfSA9IG9wdGlvbnM7XG4gIGlmICghdXNlcm5hbWUgJiYgIWVtYWlsKVxuICAgIHRocm93IG5ldyBNZXRlb3IuRXJyb3IoNDAwLCBcIk5lZWQgdG8gc2V0IGEgdXNlcm5hbWUgb3IgZW1haWxcIik7XG5cbiAgY29uc3QgdXNlciA9IHtzZXJ2aWNlczoge319O1xuICBpZiAocGFzc3dvcmQpIHtcbiAgICBjb25zdCBoYXNoZWQgPSBoYXNoUGFzc3dvcmQocGFzc3dvcmQpO1xuICAgIHVzZXIuc2VydmljZXMucGFzc3dvcmQgPSB7IGJjcnlwdDogaGFzaGVkIH07XG4gIH1cblxuICBpZiAodXNlcm5hbWUpXG4gICAgdXNlci51c2VybmFtZSA9IHVzZXJuYW1lO1xuICBpZiAoZW1haWwpXG4gICAgdXNlci5lbWFpbHMgPSBbe2FkZHJlc3M6IGVtYWlsLCB2ZXJpZmllZDogZmFsc2V9XTtcblxuICAvLyBQZXJmb3JtIGEgY2FzZSBpbnNlbnNpdGl2ZSBjaGVjayBiZWZvcmUgaW5zZXJ0XG4gIGNoZWNrRm9yQ2FzZUluc2Vuc2l0aXZlRHVwbGljYXRlcygndXNlcm5hbWUnLCAnVXNlcm5hbWUnLCB1c2VybmFtZSk7XG4gIGNoZWNrRm9yQ2FzZUluc2Vuc2l0aXZlRHVwbGljYXRlcygnZW1haWxzLmFkZHJlc3MnLCAnRW1haWwnLCBlbWFpbCk7XG5cbiAgY29uc3QgdXNlcklkID0gQWNjb3VudHMuaW5zZXJ0VXNlckRvYyhvcHRpb25zLCB1c2VyKTtcbiAgLy8gUGVyZm9ybSBhbm90aGVyIGNoZWNrIGFmdGVyIGluc2VydCwgaW4gY2FzZSBhIG1hdGNoaW5nIHVzZXIgaGFzIGJlZW5cbiAgLy8gaW5zZXJ0ZWQgaW4gdGhlIG1lYW50aW1lXG4gIHRyeSB7XG4gICAgY2hlY2tGb3JDYXNlSW5zZW5zaXRpdmVEdXBsaWNhdGVzKCd1c2VybmFtZScsICdVc2VybmFtZScsIHVzZXJuYW1lLCB1c2VySWQpO1xuICAgIGNoZWNrRm9yQ2FzZUluc2Vuc2l0aXZlRHVwbGljYXRlcygnZW1haWxzLmFkZHJlc3MnLCAnRW1haWwnLCBlbWFpbCwgdXNlcklkKTtcbiAgfSBjYXRjaCAoZXgpIHtcbiAgICAvLyBSZW1vdmUgaW5zZXJ0ZWQgdXNlciBpZiB0aGUgY2hlY2sgZmFpbHNcbiAgICBNZXRlb3IudXNlcnMucmVtb3ZlKHVzZXJJZCk7XG4gICAgdGhyb3cgZXg7XG4gIH1cbiAgcmV0dXJuIHVzZXJJZDtcbn07XG5cbi8vIG1ldGhvZCBmb3IgY3JlYXRlIHVzZXIuIFJlcXVlc3RzIGNvbWUgZnJvbSB0aGUgY2xpZW50LlxuTWV0ZW9yLm1ldGhvZHMoe2NyZWF0ZVVzZXI6IGZ1bmN0aW9uICguLi5hcmdzKSB7XG4gIGNvbnN0IG9wdGlvbnMgPSBhcmdzWzBdO1xuICByZXR1cm4gQWNjb3VudHMuX2xvZ2luTWV0aG9kKFxuICAgIHRoaXMsXG4gICAgXCJjcmVhdGVVc2VyXCIsXG4gICAgYXJncyxcbiAgICBcInBhc3N3b3JkXCIsXG4gICAgKCkgPT4ge1xuICAgICAgLy8gY3JlYXRlVXNlcigpIGFib3ZlIGRvZXMgbW9yZSBjaGVja2luZy5cbiAgICAgIGNoZWNrKG9wdGlvbnMsIE9iamVjdCk7XG4gICAgICBpZiAoQWNjb3VudHMuX29wdGlvbnMuZm9yYmlkQ2xpZW50QWNjb3VudENyZWF0aW9uKVxuICAgICAgICByZXR1cm4ge1xuICAgICAgICAgIGVycm9yOiBuZXcgTWV0ZW9yLkVycm9yKDQwMywgXCJTaWdudXBzIGZvcmJpZGRlblwiKVxuICAgICAgICB9O1xuXG4gICAgICAvLyBDcmVhdGUgdXNlci4gcmVzdWx0IGNvbnRhaW5zIGlkIGFuZCB0b2tlbi5cbiAgICAgIGNvbnN0IHVzZXJJZCA9IGNyZWF0ZVVzZXIob3B0aW9ucyk7XG4gICAgICAvLyBzYWZldHkgYmVsdC4gY3JlYXRlVXNlciBpcyBzdXBwb3NlZCB0byB0aHJvdyBvbiBlcnJvci4gc2VuZCA1MDAgZXJyb3JcbiAgICAgIC8vIGluc3RlYWQgb2Ygc2VuZGluZyBhIHZlcmlmaWNhdGlvbiBlbWFpbCB3aXRoIGVtcHR5IHVzZXJpZC5cbiAgICAgIGlmICghIHVzZXJJZClcbiAgICAgICAgdGhyb3cgbmV3IEVycm9yKFwiY3JlYXRlVXNlciBmYWlsZWQgdG8gaW5zZXJ0IG5ldyB1c2VyXCIpO1xuXG4gICAgICAvLyBJZiBgQWNjb3VudHMuX29wdGlvbnMuc2VuZFZlcmlmaWNhdGlvbkVtYWlsYCBpcyBzZXQsIHJlZ2lzdGVyXG4gICAgICAvLyBhIHRva2VuIHRvIHZlcmlmeSB0aGUgdXNlcidzIHByaW1hcnkgZW1haWwsIGFuZCBzZW5kIGl0IHRvXG4gICAgICAvLyB0aGF0IGFkZHJlc3MuXG4gICAgICBpZiAob3B0aW9ucy5lbWFpbCAmJiBBY2NvdW50cy5fb3B0aW9ucy5zZW5kVmVyaWZpY2F0aW9uRW1haWwpXG4gICAgICAgIEFjY291bnRzLnNlbmRWZXJpZmljYXRpb25FbWFpbCh1c2VySWQsIG9wdGlvbnMuZW1haWwpO1xuXG4gICAgICAvLyBjbGllbnQgZ2V0cyBsb2dnZWQgaW4gYXMgdGhlIG5ldyB1c2VyIGFmdGVyd2FyZHMuXG4gICAgICByZXR1cm4ge3VzZXJJZDogdXNlcklkfTtcbiAgICB9XG4gICk7XG59fSk7XG5cbi8vIENyZWF0ZSB1c2VyIGRpcmVjdGx5IG9uIHRoZSBzZXJ2ZXIuXG4vL1xuLy8gVW5saWtlIHRoZSBjbGllbnQgdmVyc2lvbiwgdGhpcyBkb2VzIG5vdCBsb2cgeW91IGluIGFzIHRoaXMgdXNlclxuLy8gYWZ0ZXIgY3JlYXRpb24uXG4vL1xuLy8gcmV0dXJucyB1c2VySWQgb3IgdGhyb3dzIGFuIGVycm9yIGlmIGl0IGNhbid0IGNyZWF0ZVxuLy9cbi8vIFhYWCBhZGQgYW5vdGhlciBhcmd1bWVudCAoXCJzZXJ2ZXIgb3B0aW9uc1wiKSB0aGF0IGdldHMgc2VudCB0byBvbkNyZWF0ZVVzZXIsXG4vLyB3aGljaCBpcyBhbHdheXMgZW1wdHkgd2hlbiBjYWxsZWQgZnJvbSB0aGUgY3JlYXRlVXNlciBtZXRob2Q/IGVnLCBcImFkbWluOlxuLy8gdHJ1ZVwiLCB3aGljaCB3ZSB3YW50IHRvIHByZXZlbnQgdGhlIGNsaWVudCBmcm9tIHNldHRpbmcsIGJ1dCB3aGljaCBhIGN1c3RvbVxuLy8gbWV0aG9kIGNhbGxpbmcgQWNjb3VudHMuY3JlYXRlVXNlciBjb3VsZCBzZXQ/XG4vL1xuQWNjb3VudHMuY3JlYXRlVXNlciA9IChvcHRpb25zLCBjYWxsYmFjaykgPT4ge1xuICBvcHRpb25zID0geyAuLi5vcHRpb25zIH07XG5cbiAgLy8gWFhYIGFsbG93IGFuIG9wdGlvbmFsIGNhbGxiYWNrP1xuICBpZiAoY2FsbGJhY2spIHtcbiAgICB0aHJvdyBuZXcgRXJyb3IoXCJBY2NvdW50cy5jcmVhdGVVc2VyIHdpdGggY2FsbGJhY2sgbm90IHN1cHBvcnRlZCBvbiB0aGUgc2VydmVyIHlldC5cIik7XG4gIH1cblxuICByZXR1cm4gY3JlYXRlVXNlcihvcHRpb25zKTtcbn07XG5cbi8vL1xuLy8vIFBBU1NXT1JELVNQRUNJRklDIElOREVYRVMgT04gVVNFUlNcbi8vL1xuTWV0ZW9yLnVzZXJzLl9lbnN1cmVJbmRleCgnc2VydmljZXMuZW1haWwudmVyaWZpY2F0aW9uVG9rZW5zLnRva2VuJyxcbiAgICAgICAgICAgICAgICAgICAgICAgICAgeyB1bmlxdWU6IHRydWUsIHNwYXJzZTogdHJ1ZSB9KTtcbk1ldGVvci51c2Vycy5fZW5zdXJlSW5kZXgoJ3NlcnZpY2VzLnBhc3N3b3JkLnJlc2V0LnRva2VuJyxcbiAgICAgICAgICAgICAgICAgICAgICAgICAgeyB1bmlxdWU6IHRydWUsIHNwYXJzZTogdHJ1ZSB9KTtcbiJdfQ==
