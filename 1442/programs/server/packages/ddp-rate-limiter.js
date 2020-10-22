(function () {

/* Imports */
var Meteor = Package.meteor.Meteor;
var global = Package.meteor.global;
var meteorEnv = Package.meteor.meteorEnv;
var RateLimiter = Package['rate-limit'].RateLimiter;
var ECMAScript = Package.ecmascript.ECMAScript;
var meteorInstall = Package.modules.meteorInstall;
var Promise = Package.promise.Promise;

/* Package-scope variables */
var DDPRateLimiter;

var require = meteorInstall({"node_modules":{"meteor":{"ddp-rate-limiter":{"ddp-rate-limiter.js":function module(require,exports,module){

//////////////////////////////////////////////////////////////////////////////////
//                                                                              //
// packages/ddp-rate-limiter/ddp-rate-limiter.js                                //
//                                                                              //
//////////////////////////////////////////////////////////////////////////////////
                                                                                //
module.export({
  DDPRateLimiter: () => DDPRateLimiter
});
let RateLimiter;
module.link("meteor/rate-limit", {
  RateLimiter(v) {
    RateLimiter = v;
  }

}, 0);
// Rate Limiter built into DDP with a default error message. See README or
// online documentation for more details.
const DDPRateLimiter = {};

let errorMessage = rateLimitResult => {
  return 'Error, too many requests. Please slow down. You must wait ' + "".concat(Math.ceil(rateLimitResult.timeToReset / 1000), " seconds before ") + 'trying again.';
};

const rateLimiter = new RateLimiter();

DDPRateLimiter.getErrorMessage = rateLimitResult => {
  if (typeof errorMessage === 'function') {
    return errorMessage(rateLimitResult);
  } else {
    return errorMessage;
  }
};
/**
 * @summary Set error message text when method or subscription rate limit
 * exceeded.
 * @param {string|function} message Functions are passed in an object with a
 * `timeToReset` field that specifies the number of milliseconds until the next
 * method or subscription is allowed to run. The function must return a string
 * of the error message.
 * @locus Server
 */


DDPRateLimiter.setErrorMessage = message => {
  errorMessage = message;
};
/**
 * @summary
 * Add a rule that matches against a stream of events describing method or
 * subscription attempts. Each event is an object with the following
 * properties:
 *
 * - `type`: Either "method" or "subscription"
 * - `name`: The name of the method or subscription being called
 * - `userId`: The user ID attempting the method or subscription
 * - `connectionId`: A string representing the user's DDP connection
 * - `clientAddress`: The IP address of the user
 *
 * Returns unique `ruleId` that can be passed to `removeRule`.
 *
 * @param {Object} matcher
 *   Matchers specify which events are counted towards a rate limit. A matcher
 *   is an object that has a subset of the same properties as the event objects
 *   described above. Each value in a matcher object is one of the following:
 *
 *   - a string: for the event to satisfy the matcher, this value must be equal
 *   to the value of the same property in the event object
 *
 *   - a function: for the event to satisfy the matcher, the function must
 *   evaluate to true when passed the value of the same property
 *   in the event object
 *
 * Here's how events are counted: Each event that satisfies the matcher's
 * filter is mapped to a bucket. Buckets are uniquely determined by the
 * event object's values for all properties present in both the matcher and
 * event objects.
 *
 * @param {number} numRequests  number of requests allowed per time interval.
 * Default = 10.
 * @param {number} timeInterval time interval in milliseconds after which
 * rule's counters are reset. Default = 1000.
 * @param {function} callback function to be called after a rule is executed.
 * @locus Server
 */


DDPRateLimiter.addRule = (matcher, numRequests, timeInterval, callback) => rateLimiter.addRule(matcher, numRequests, timeInterval, callback);

DDPRateLimiter.printRules = () => rateLimiter.rules;
/**
 * @summary Removes the specified rule from the rate limiter. If rule had
 * hit a rate limit, that limit is removed as well.
 * @param  {string} id 'ruleId' returned from `addRule`
 * @return {boolean}    True if a rule was removed.
 * @locus Server
 */


DDPRateLimiter.removeRule = id => rateLimiter.removeRule(id); // This is accessed inside livedata_server.js, but shouldn't be called by any
// user.


DDPRateLimiter._increment = input => {
  rateLimiter.increment(input);
};

DDPRateLimiter._check = input => rateLimiter.check(input);
//////////////////////////////////////////////////////////////////////////////////

}}}}},{
  "extensions": [
    ".js",
    ".json"
  ]
});

var exports = require("/node_modules/meteor/ddp-rate-limiter/ddp-rate-limiter.js");

/* Exports */
Package._define("ddp-rate-limiter", exports, {
  DDPRateLimiter: DDPRateLimiter
});

})();

//# sourceURL=meteor://💻app/packages/ddp-rate-limiter.js
//# sourceMappingURL=data:application/json;charset=utf8;base64,eyJ2ZXJzaW9uIjozLCJzb3VyY2VzIjpbIm1ldGVvcjovL/CfkrthcHAvcGFja2FnZXMvZGRwLXJhdGUtbGltaXRlci9kZHAtcmF0ZS1saW1pdGVyLmpzIl0sIm5hbWVzIjpbIm1vZHVsZSIsImV4cG9ydCIsIkREUFJhdGVMaW1pdGVyIiwiUmF0ZUxpbWl0ZXIiLCJsaW5rIiwidiIsImVycm9yTWVzc2FnZSIsInJhdGVMaW1pdFJlc3VsdCIsIk1hdGgiLCJjZWlsIiwidGltZVRvUmVzZXQiLCJyYXRlTGltaXRlciIsImdldEVycm9yTWVzc2FnZSIsInNldEVycm9yTWVzc2FnZSIsIm1lc3NhZ2UiLCJhZGRSdWxlIiwibWF0Y2hlciIsIm51bVJlcXVlc3RzIiwidGltZUludGVydmFsIiwiY2FsbGJhY2siLCJwcmludFJ1bGVzIiwicnVsZXMiLCJyZW1vdmVSdWxlIiwiaWQiLCJfaW5jcmVtZW50IiwiaW5wdXQiLCJpbmNyZW1lbnQiLCJfY2hlY2siLCJjaGVjayJdLCJtYXBwaW5ncyI6Ijs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7OztBQUFBQSxNQUFNLENBQUNDLE1BQVAsQ0FBYztBQUFDQyxnQkFBYyxFQUFDLE1BQUlBO0FBQXBCLENBQWQ7QUFBbUQsSUFBSUMsV0FBSjtBQUFnQkgsTUFBTSxDQUFDSSxJQUFQLENBQVksbUJBQVosRUFBZ0M7QUFBQ0QsYUFBVyxDQUFDRSxDQUFELEVBQUc7QUFBQ0YsZUFBVyxHQUFDRSxDQUFaO0FBQWM7O0FBQTlCLENBQWhDLEVBQWdFLENBQWhFO0FBRW5FO0FBQ0E7QUFDQSxNQUFNSCxjQUFjLEdBQUcsRUFBdkI7O0FBRUEsSUFBSUksWUFBWSxHQUFJQyxlQUFELElBQXFCO0FBQ3RDLFNBQU8seUVBQ0ZDLElBQUksQ0FBQ0MsSUFBTCxDQUFVRixlQUFlLENBQUNHLFdBQWhCLEdBQThCLElBQXhDLENBREUsd0JBRUwsZUFGRjtBQUdELENBSkQ7O0FBTUEsTUFBTUMsV0FBVyxHQUFHLElBQUlSLFdBQUosRUFBcEI7O0FBRUFELGNBQWMsQ0FBQ1UsZUFBZixHQUFrQ0wsZUFBRCxJQUFxQjtBQUNwRCxNQUFJLE9BQU9ELFlBQVAsS0FBd0IsVUFBNUIsRUFBd0M7QUFDdEMsV0FBT0EsWUFBWSxDQUFDQyxlQUFELENBQW5CO0FBQ0QsR0FGRCxNQUVPO0FBQ0wsV0FBT0QsWUFBUDtBQUNEO0FBQ0YsQ0FORDtBQVFBOzs7Ozs7Ozs7OztBQVNBSixjQUFjLENBQUNXLGVBQWYsR0FBa0NDLE9BQUQsSUFBYTtBQUM1Q1IsY0FBWSxHQUFHUSxPQUFmO0FBQ0QsQ0FGRDtBQUlBOzs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7O0FBc0NBWixjQUFjLENBQUNhLE9BQWYsR0FBeUIsQ0FBQ0MsT0FBRCxFQUFVQyxXQUFWLEVBQXVCQyxZQUF2QixFQUFxQ0MsUUFBckMsS0FDdkJSLFdBQVcsQ0FBQ0ksT0FBWixDQUFvQkMsT0FBcEIsRUFBNkJDLFdBQTdCLEVBQTBDQyxZQUExQyxFQUF3REMsUUFBeEQsQ0FERjs7QUFHQWpCLGNBQWMsQ0FBQ2tCLFVBQWYsR0FBNEIsTUFBTVQsV0FBVyxDQUFDVSxLQUE5QztBQUVBOzs7Ozs7Ozs7QUFPQW5CLGNBQWMsQ0FBQ29CLFVBQWYsR0FBNEJDLEVBQUUsSUFBSVosV0FBVyxDQUFDVyxVQUFaLENBQXVCQyxFQUF2QixDQUFsQyxDLENBRUE7QUFDQTs7O0FBQ0FyQixjQUFjLENBQUNzQixVQUFmLEdBQTZCQyxLQUFELElBQVc7QUFDckNkLGFBQVcsQ0FBQ2UsU0FBWixDQUFzQkQsS0FBdEI7QUFDRCxDQUZEOztBQUlBdkIsY0FBYyxDQUFDeUIsTUFBZixHQUF3QkYsS0FBSyxJQUFJZCxXQUFXLENBQUNpQixLQUFaLENBQWtCSCxLQUFsQixDQUFqQyxDIiwiZmlsZSI6Ii9wYWNrYWdlcy9kZHAtcmF0ZS1saW1pdGVyLmpzIiwic291cmNlc0NvbnRlbnQiOlsiaW1wb3J0IHsgUmF0ZUxpbWl0ZXIgfSBmcm9tICdtZXRlb3IvcmF0ZS1saW1pdCc7XG5cbi8vIFJhdGUgTGltaXRlciBidWlsdCBpbnRvIEREUCB3aXRoIGEgZGVmYXVsdCBlcnJvciBtZXNzYWdlLiBTZWUgUkVBRE1FIG9yXG4vLyBvbmxpbmUgZG9jdW1lbnRhdGlvbiBmb3IgbW9yZSBkZXRhaWxzLlxuY29uc3QgRERQUmF0ZUxpbWl0ZXIgPSB7fTtcblxubGV0IGVycm9yTWVzc2FnZSA9IChyYXRlTGltaXRSZXN1bHQpID0+IHtcbiAgcmV0dXJuICdFcnJvciwgdG9vIG1hbnkgcmVxdWVzdHMuIFBsZWFzZSBzbG93IGRvd24uIFlvdSBtdXN0IHdhaXQgJyArXG4gICAgYCR7TWF0aC5jZWlsKHJhdGVMaW1pdFJlc3VsdC50aW1lVG9SZXNldCAvIDEwMDApfSBzZWNvbmRzIGJlZm9yZSBgICtcbiAgICAndHJ5aW5nIGFnYWluLic7XG59O1xuXG5jb25zdCByYXRlTGltaXRlciA9IG5ldyBSYXRlTGltaXRlcigpO1xuXG5ERFBSYXRlTGltaXRlci5nZXRFcnJvck1lc3NhZ2UgPSAocmF0ZUxpbWl0UmVzdWx0KSA9PiB7XG4gIGlmICh0eXBlb2YgZXJyb3JNZXNzYWdlID09PSAnZnVuY3Rpb24nKSB7XG4gICAgcmV0dXJuIGVycm9yTWVzc2FnZShyYXRlTGltaXRSZXN1bHQpO1xuICB9IGVsc2Uge1xuICAgIHJldHVybiBlcnJvck1lc3NhZ2U7XG4gIH1cbn07XG5cbi8qKlxuICogQHN1bW1hcnkgU2V0IGVycm9yIG1lc3NhZ2UgdGV4dCB3aGVuIG1ldGhvZCBvciBzdWJzY3JpcHRpb24gcmF0ZSBsaW1pdFxuICogZXhjZWVkZWQuXG4gKiBAcGFyYW0ge3N0cmluZ3xmdW5jdGlvbn0gbWVzc2FnZSBGdW5jdGlvbnMgYXJlIHBhc3NlZCBpbiBhbiBvYmplY3Qgd2l0aCBhXG4gKiBgdGltZVRvUmVzZXRgIGZpZWxkIHRoYXQgc3BlY2lmaWVzIHRoZSBudW1iZXIgb2YgbWlsbGlzZWNvbmRzIHVudGlsIHRoZSBuZXh0XG4gKiBtZXRob2Qgb3Igc3Vic2NyaXB0aW9uIGlzIGFsbG93ZWQgdG8gcnVuLiBUaGUgZnVuY3Rpb24gbXVzdCByZXR1cm4gYSBzdHJpbmdcbiAqIG9mIHRoZSBlcnJvciBtZXNzYWdlLlxuICogQGxvY3VzIFNlcnZlclxuICovXG5ERFBSYXRlTGltaXRlci5zZXRFcnJvck1lc3NhZ2UgPSAobWVzc2FnZSkgPT4ge1xuICBlcnJvck1lc3NhZ2UgPSBtZXNzYWdlO1xufTtcblxuLyoqXG4gKiBAc3VtbWFyeVxuICogQWRkIGEgcnVsZSB0aGF0IG1hdGNoZXMgYWdhaW5zdCBhIHN0cmVhbSBvZiBldmVudHMgZGVzY3JpYmluZyBtZXRob2Qgb3JcbiAqIHN1YnNjcmlwdGlvbiBhdHRlbXB0cy4gRWFjaCBldmVudCBpcyBhbiBvYmplY3Qgd2l0aCB0aGUgZm9sbG93aW5nXG4gKiBwcm9wZXJ0aWVzOlxuICpcbiAqIC0gYHR5cGVgOiBFaXRoZXIgXCJtZXRob2RcIiBvciBcInN1YnNjcmlwdGlvblwiXG4gKiAtIGBuYW1lYDogVGhlIG5hbWUgb2YgdGhlIG1ldGhvZCBvciBzdWJzY3JpcHRpb24gYmVpbmcgY2FsbGVkXG4gKiAtIGB1c2VySWRgOiBUaGUgdXNlciBJRCBhdHRlbXB0aW5nIHRoZSBtZXRob2Qgb3Igc3Vic2NyaXB0aW9uXG4gKiAtIGBjb25uZWN0aW9uSWRgOiBBIHN0cmluZyByZXByZXNlbnRpbmcgdGhlIHVzZXIncyBERFAgY29ubmVjdGlvblxuICogLSBgY2xpZW50QWRkcmVzc2A6IFRoZSBJUCBhZGRyZXNzIG9mIHRoZSB1c2VyXG4gKlxuICogUmV0dXJucyB1bmlxdWUgYHJ1bGVJZGAgdGhhdCBjYW4gYmUgcGFzc2VkIHRvIGByZW1vdmVSdWxlYC5cbiAqXG4gKiBAcGFyYW0ge09iamVjdH0gbWF0Y2hlclxuICogICBNYXRjaGVycyBzcGVjaWZ5IHdoaWNoIGV2ZW50cyBhcmUgY291bnRlZCB0b3dhcmRzIGEgcmF0ZSBsaW1pdC4gQSBtYXRjaGVyXG4gKiAgIGlzIGFuIG9iamVjdCB0aGF0IGhhcyBhIHN1YnNldCBvZiB0aGUgc2FtZSBwcm9wZXJ0aWVzIGFzIHRoZSBldmVudCBvYmplY3RzXG4gKiAgIGRlc2NyaWJlZCBhYm92ZS4gRWFjaCB2YWx1ZSBpbiBhIG1hdGNoZXIgb2JqZWN0IGlzIG9uZSBvZiB0aGUgZm9sbG93aW5nOlxuICpcbiAqICAgLSBhIHN0cmluZzogZm9yIHRoZSBldmVudCB0byBzYXRpc2Z5IHRoZSBtYXRjaGVyLCB0aGlzIHZhbHVlIG11c3QgYmUgZXF1YWxcbiAqICAgdG8gdGhlIHZhbHVlIG9mIHRoZSBzYW1lIHByb3BlcnR5IGluIHRoZSBldmVudCBvYmplY3RcbiAqXG4gKiAgIC0gYSBmdW5jdGlvbjogZm9yIHRoZSBldmVudCB0byBzYXRpc2Z5IHRoZSBtYXRjaGVyLCB0aGUgZnVuY3Rpb24gbXVzdFxuICogICBldmFsdWF0ZSB0byB0cnVlIHdoZW4gcGFzc2VkIHRoZSB2YWx1ZSBvZiB0aGUgc2FtZSBwcm9wZXJ0eVxuICogICBpbiB0aGUgZXZlbnQgb2JqZWN0XG4gKlxuICogSGVyZSdzIGhvdyBldmVudHMgYXJlIGNvdW50ZWQ6IEVhY2ggZXZlbnQgdGhhdCBzYXRpc2ZpZXMgdGhlIG1hdGNoZXInc1xuICogZmlsdGVyIGlzIG1hcHBlZCB0byBhIGJ1Y2tldC4gQnVja2V0cyBhcmUgdW5pcXVlbHkgZGV0ZXJtaW5lZCBieSB0aGVcbiAqIGV2ZW50IG9iamVjdCdzIHZhbHVlcyBmb3IgYWxsIHByb3BlcnRpZXMgcHJlc2VudCBpbiBib3RoIHRoZSBtYXRjaGVyIGFuZFxuICogZXZlbnQgb2JqZWN0cy5cbiAqXG4gKiBAcGFyYW0ge251bWJlcn0gbnVtUmVxdWVzdHMgIG51bWJlciBvZiByZXF1ZXN0cyBhbGxvd2VkIHBlciB0aW1lIGludGVydmFsLlxuICogRGVmYXVsdCA9IDEwLlxuICogQHBhcmFtIHtudW1iZXJ9IHRpbWVJbnRlcnZhbCB0aW1lIGludGVydmFsIGluIG1pbGxpc2Vjb25kcyBhZnRlciB3aGljaFxuICogcnVsZSdzIGNvdW50ZXJzIGFyZSByZXNldC4gRGVmYXVsdCA9IDEwMDAuXG4gKiBAcGFyYW0ge2Z1bmN0aW9ufSBjYWxsYmFjayBmdW5jdGlvbiB0byBiZSBjYWxsZWQgYWZ0ZXIgYSBydWxlIGlzIGV4ZWN1dGVkLlxuICogQGxvY3VzIFNlcnZlclxuICovXG5ERFBSYXRlTGltaXRlci5hZGRSdWxlID0gKG1hdGNoZXIsIG51bVJlcXVlc3RzLCB0aW1lSW50ZXJ2YWwsIGNhbGxiYWNrKSA9PiBcbiAgcmF0ZUxpbWl0ZXIuYWRkUnVsZShtYXRjaGVyLCBudW1SZXF1ZXN0cywgdGltZUludGVydmFsLCBjYWxsYmFjayk7XG5cbkREUFJhdGVMaW1pdGVyLnByaW50UnVsZXMgPSAoKSA9PiByYXRlTGltaXRlci5ydWxlcztcblxuLyoqXG4gKiBAc3VtbWFyeSBSZW1vdmVzIHRoZSBzcGVjaWZpZWQgcnVsZSBmcm9tIHRoZSByYXRlIGxpbWl0ZXIuIElmIHJ1bGUgaGFkXG4gKiBoaXQgYSByYXRlIGxpbWl0LCB0aGF0IGxpbWl0IGlzIHJlbW92ZWQgYXMgd2VsbC5cbiAqIEBwYXJhbSAge3N0cmluZ30gaWQgJ3J1bGVJZCcgcmV0dXJuZWQgZnJvbSBgYWRkUnVsZWBcbiAqIEByZXR1cm4ge2Jvb2xlYW59ICAgIFRydWUgaWYgYSBydWxlIHdhcyByZW1vdmVkLlxuICogQGxvY3VzIFNlcnZlclxuICovXG5ERFBSYXRlTGltaXRlci5yZW1vdmVSdWxlID0gaWQgPT4gcmF0ZUxpbWl0ZXIucmVtb3ZlUnVsZShpZCk7XG5cbi8vIFRoaXMgaXMgYWNjZXNzZWQgaW5zaWRlIGxpdmVkYXRhX3NlcnZlci5qcywgYnV0IHNob3VsZG4ndCBiZSBjYWxsZWQgYnkgYW55XG4vLyB1c2VyLlxuRERQUmF0ZUxpbWl0ZXIuX2luY3JlbWVudCA9IChpbnB1dCkgPT4ge1xuICByYXRlTGltaXRlci5pbmNyZW1lbnQoaW5wdXQpO1xufTtcblxuRERQUmF0ZUxpbWl0ZXIuX2NoZWNrID0gaW5wdXQgPT4gcmF0ZUxpbWl0ZXIuY2hlY2soaW5wdXQpO1xuXG5leHBvcnQgeyBERFBSYXRlTGltaXRlciB9O1xuIl19
