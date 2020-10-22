(function () {

/* Imports */
var Meteor = Package.meteor.Meteor;
var global = Package.meteor.global;
var meteorEnv = Package.meteor.meteorEnv;
var ECMAScript = Package.ecmascript.ECMAScript;
var MongoInternals = Package.mongo.MongoInternals;
var Mongo = Package.mongo.Mongo;
var Email = Package.email.Email;
var EmailInternals = Package.email.EmailInternals;
var HTTP = Package.http.HTTP;
var HTTPInternals = Package.http.HTTPInternals;
var meteorInstall = Package.modules.meteorInstall;
var Promise = Package.promise.Promise;

var require = meteorInstall({"node_modules":{"meteor":{"rocketchat:mongo-config":{"server":{"index.js":function module(require,exports,module){

///////////////////////////////////////////////////////////////////////////////////////////////////////
//                                                                                                   //
// packages/rocketchat_mongo-config/server/index.js                                                  //
//                                                                                                   //
///////////////////////////////////////////////////////////////////////////////////////////////////////
                                                                                                     //
let _objectSpread;

module.link("@babel/runtime/helpers/objectSpread2", {
  default(v) {
    _objectSpread = v;
  }

}, 0);
let tls;
module.link("tls", {
  default(v) {
    tls = v;
  }

}, 0);
let PassThrough;
module.link("stream", {
  PassThrough(v) {
    PassThrough = v;
  }

}, 1);
let EmailTest;
module.link("meteor/email", {
  EmailTest(v) {
    EmailTest = v;
  }

}, 2);
let Mongo;
module.link("meteor/mongo", {
  Mongo(v) {
    Mongo = v;
  }

}, 3);
let HTTP;
module.link("meteor/http", {
  HTTP(v) {
    HTTP = v;
  }

}, 4);
// Set default HTTP call timeout to 20s
const envTimeout = parseInt(process.env.HTTP_DEFAULT_TIMEOUT, 10);
const timeout = !isNaN(envTimeout) ? envTimeout : 20000;
const {
  call
} = HTTP;

HTTP.call = function _call(method, url) {
  let options = arguments.length > 2 && arguments[2] !== undefined ? arguments[2] : {};
  let callback = arguments.length > 3 ? arguments[3] : undefined;
  const defaultTimeout = 'timeout' in options ? options : _objectSpread({}, options, {
    timeout
  });
  return call.call(HTTP, method, url, defaultTimeout, callback);
}; // FIX For TLS error see more here https://github.com/RocketChat/Rocket.Chat/issues/9316
// TODO: Remove after NodeJS fix it, more information
// https://github.com/nodejs/node/issues/16196
// https://github.com/nodejs/node/pull/16853
// This is fixed in Node 10, but this supports LTS versions


tls.DEFAULT_ECDH_CURVE = 'auto';

const mongoConnectionOptions = _objectSpread({}, !process.env.MONGO_URL.includes('retryWrites') && {
  retryWrites: false
});

const mongoOptionStr = process.env.MONGO_OPTIONS;

if (typeof mongoOptionStr !== 'undefined') {
  const mongoOptions = JSON.parse(mongoOptionStr);
  Object.assign(mongoConnectionOptions, mongoOptions);
}

if (Object.keys(mongoConnectionOptions).length > 0) {
  Mongo.setConnectionOptions(mongoConnectionOptions);
}

process.env.HTTP_FORWARDED_COUNT = process.env.HTTP_FORWARDED_COUNT || '1'; // Send emails to a "fake" stream instead of print them in console

if (process.env.NODE_ENV !== 'development' || process.env.TEST_MODE) {
  const stream = new PassThrough();
  EmailTest.overrideOutputStream(stream);
  stream.on('data', () => {});
  stream.on('end', () => {});
}
///////////////////////////////////////////////////////////////////////////////////////////////////////

}}}}}},{
  "extensions": [
    ".js",
    ".json"
  ]
});

var exports = require("/node_modules/meteor/rocketchat:mongo-config/server/index.js");

/* Exports */
Package._define("rocketchat:mongo-config", exports);

})();

//# sourceURL=meteor://💻app/packages/rocketchat_mongo-config.js
//# sourceMappingURL=data:application/json;charset=utf8;base64,eyJ2ZXJzaW9uIjozLCJzb3VyY2VzIjpbIm1ldGVvcjovL/CfkrthcHAvcGFja2FnZXMvcm9ja2V0Y2hhdDptb25nby1jb25maWcvc2VydmVyL2luZGV4LmpzIl0sIm5hbWVzIjpbIl9vYmplY3RTcHJlYWQiLCJtb2R1bGUiLCJsaW5rIiwiZGVmYXVsdCIsInYiLCJ0bHMiLCJQYXNzVGhyb3VnaCIsIkVtYWlsVGVzdCIsIk1vbmdvIiwiSFRUUCIsImVudlRpbWVvdXQiLCJwYXJzZUludCIsInByb2Nlc3MiLCJlbnYiLCJIVFRQX0RFRkFVTFRfVElNRU9VVCIsInRpbWVvdXQiLCJpc05hTiIsImNhbGwiLCJfY2FsbCIsIm1ldGhvZCIsInVybCIsIm9wdGlvbnMiLCJjYWxsYmFjayIsImRlZmF1bHRUaW1lb3V0IiwiREVGQVVMVF9FQ0RIX0NVUlZFIiwibW9uZ29Db25uZWN0aW9uT3B0aW9ucyIsIk1PTkdPX1VSTCIsImluY2x1ZGVzIiwicmV0cnlXcml0ZXMiLCJtb25nb09wdGlvblN0ciIsIk1PTkdPX09QVElPTlMiLCJtb25nb09wdGlvbnMiLCJKU09OIiwicGFyc2UiLCJPYmplY3QiLCJhc3NpZ24iLCJrZXlzIiwibGVuZ3RoIiwic2V0Q29ubmVjdGlvbk9wdGlvbnMiLCJIVFRQX0ZPUldBUkRFRF9DT1VOVCIsIk5PREVfRU5WIiwiVEVTVF9NT0RFIiwic3RyZWFtIiwib3ZlcnJpZGVPdXRwdXRTdHJlYW0iLCJvbiJdLCJtYXBwaW5ncyI6Ijs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7O0FBQUEsSUFBSUEsYUFBSjs7QUFBa0JDLE1BQU0sQ0FBQ0MsSUFBUCxDQUFZLHNDQUFaLEVBQW1EO0FBQUNDLFNBQU8sQ0FBQ0MsQ0FBRCxFQUFHO0FBQUNKLGlCQUFhLEdBQUNJLENBQWQ7QUFBZ0I7O0FBQTVCLENBQW5ELEVBQWlGLENBQWpGO0FBQWxCLElBQUlDLEdBQUo7QUFBUUosTUFBTSxDQUFDQyxJQUFQLENBQVksS0FBWixFQUFrQjtBQUFDQyxTQUFPLENBQUNDLENBQUQsRUFBRztBQUFDQyxPQUFHLEdB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QWY7QUFDQUMsV0FBUyxDQUFDb0Msb0JBQVYsQ0FBK0JELE1BQS9CO0FBQ0FBLFFBQU0sQ0FBQ0UsRUFBUCxDQUFVLE1BQVYsRUFBa0IsTUFBTSxDQUFFLENBQTFCO0FBQ0FGLFFBQU0sQ0FBQ0UsRUFBUCxDQUFVLEtBQVYsRUFBaUIsTUFBTSxDQUFFLENBQXpCO0FBQ0EsQyIsImZpbGUiOiIvcGFja2FnZXMvcm9ja2V0Y2hhdF9tb25nby1jb25maWcuanMiLCJzb3VyY2VzQ29udGVudCI6WyJpbXBvcnQgdGxzIGZyb20gJ3Rscyc7XG5pbXBvcnQgeyBQYXNzVGhyb3VnaCB9IGZyb20gJ3N0cmVhbSc7XG5cbmltcG9ydCB7IEVtYWlsVGVzdCB9IGZyb20gJ21ldGVvci9lbWFpbCc7XG5pbXBvcnQgeyBNb25nbyB9IGZyb20gJ21ldGVvci9tb25nbyc7XG5pbXBvcnQgeyBIVFRQIH0gZnJvbSAnbWV0ZW9yL2h0dHAnO1xuXG4vLyBTZXQgZGVmYXVsdCBIVFRQIGNhbGwgdGltZW91dCB0byAyMHNcbmNvbnN0IGVudlRpbWVvdXQgPSBwYXJzZUludChwcm9jZXNzLmVudi5IVFRQX0RFRkFVTFRfVElNRU9VVCwgMTApO1xuY29uc3QgdGltZW91dCA9ICFpc05hTihlbnZUaW1lb3V0KSA/IGVudlRpbWVvdXQgOiAyMDAwMDtcblxuY29uc3QgeyBjYWxsIH0gPSBIVFRQO1xuSFRUUC5jYWxsID0gZnVuY3Rpb24gX2NhbGwobWV0aG9kLCB1cmwsIG9wdGlvbnMgPSB7fSwgY2FsbGJhY2spIHtcblx0Y29uc3QgZGVmYXVsdFRpbWVvdXQgPSAndGltZW91dCcgaW4gb3B0aW9ucyA/IG9wdGlvbnMgOiB7IC4uLm9wdGlvbnMsIHRpbWVvdXQgfTtcblxuXHRyZXR1cm4gY2FsbC5jYWxsKEhUVFAsIG1ldGhvZCwgdXJsLCBkZWZhdWx0VGltZW91dCwgY2FsbGJhY2spO1xufTtcblxuLy8gRklYIEZvciBUTFMgZXJyb3Igc2VlIG1vcmUgaGVyZSBodHRwczovL2dpdGh1Yi5jb20vUm9ja2V0Q2hhdC9Sb2NrZXQuQ2hhdC9pc3N1ZXMvOTMxNlxuLy8gVE9ETzogUmVtb3ZlIGFmdGVyIE5vZGVKUyBmaXggaXQsIG1vcmUgaW5mb3JtYXRpb25cbi8vIGh0dHBzOi8vZ2l0aHViLmNvbS9ub2RlanMvbm9kZS9pc3N1ZXMvMTYxOTZcbi8vIGh0dHBzOi8vZ2l0aHViLmNvbS9ub2RlanMvbm9kZS9wdWxsLzE2ODUzXG4vLyBUaGlzIGlzIGZpeGVkIGluIE5vZGUgMTAsIGJ1dCB0aGlzIHN1cHBvcnRzIExUUyB2ZXJzaW9uc1xudGxzLkRFRkFVTFRfRUNESF9DVVJWRSA9ICdhdXRvJztcblxuY29uc3QgbW9uZ29Db25uZWN0aW9uT3B0aW9ucyA9IHtcblx0Ly8gYWRkIHJldHJ5V3JpdGVzPWZhbHNlIGlmIG5vdCBwcmVzZW50IGluIE1PTkdPX1VSTFxuXHQuLi4hcHJvY2Vzcy5lbnYuTU9OR09fVVJMLmluY2x1ZGVzKCdyZXRyeVdyaXRlcycpICYmIHsgcmV0cnlXcml0ZXM6IGZhbHNlIH0sXG59O1xuXG5jb25zdCBtb25nb09wdGlvblN0ciA9IHByb2Nlc3MuZW52Lk1PTkdPX09QVElPTlM7XG5pZiAodHlwZW9mIG1vbmdvT3B0aW9uU3RyICE9PSAndW5kZWZpbmVkJykge1xuXHRjb25zdCBtb25nb09wdGlvbnMgPSBKU09OLnBhcnNlKG1vbmdvT3B0aW9uU3RyKTtcblxuXHRPYmplY3QuYXNzaWduKG1vbmdvQ29ubmVjdGlvbk9wdGlvbnMsIG1vbmdvT3B0aW9ucyk7XG59XG5cbmlmIChPYmplY3Qua2V5cyhtb25nb0Nvbm5lY3Rpb25PcHRpb25zKS5sZW5ndGggPiAwKSB7XG5cdE1vbmdvLnNldENvbm5lY3Rpb25PcHRpb25zKG1vbmdvQ29ubmVjdGlvbk9wdGlvbnMpO1xufVxuXG5wcm9jZXNzLmVudi5IVFRQX0ZPUldBUkRFRF9DT1VOVCA9IHByb2Nlc3MuZW52LkhUVFBfRk9SV0FSREVEX0NPVU5UIHx8ICcxJztcblxuLy8gU2VuZCBlbWFpbHMgdG8gYSBcImZha2VcIiBzdHJlYW0gaW5zdGVhZCBvZiBwcmludCB0aGVtIGluIGNvbnNvbGVcbmlmIChwcm9jZXNzLmVudi5OT0RFX0VOViAhPT0gJ2RldmVsb3BtZW50JyB8fCBwcm9jZXNzLmVudi5URVNUX01PREUpIHtcblx0Y29uc3Qgc3RyZWFtID0gbmV3IFBhc3NUaHJvdWdoKCk7XG5cdEVtYWlsVGVzdC5vdmVycmlkZU91dHB1dFN0cmVhbShzdHJlYW0pO1xuXHRzdHJlYW0ub24oJ2RhdGEnLCAoKSA9PiB7fSk7XG5cdHN0cmVhbS5vbignZW5kJywgKCkgPT4ge30pO1xufVxuIl19
