/** @module sessions
 *A module representing a user session
*/

module.exports = {
  create: create,
  destroy: destroy,
  loginRequired: loginRequired
};
var json = require('../../lib/form-json');
var encryption = require('../../lib/encryption');

/** @function create
 * Creates a new session
*/
function create(req, res, db){
  json(req, res, function(req, res){
    var username = req.body.username;
    var password = req.body.password;
      db.get('SELECT * FROM users WHERE username = ?', [username], function(err, user){
        if(err){
          res.statusCode = 500;
          res.end('Server error');
          return;
        }
        if(!user){
            // user does not exist, AHHHHHHHHHHHHHh
          res.statusCode = 403;
          res.end('Incorrect username/password');
          return;
        }
        var cryptedPassword = encryption.digest(password + user.salt);
        if(cryptedPassword != user.cryptedPassword){
          // :(
          res.statusCode = 403;
          res.end('Incorrect username/password');
        }else{
          // :)
          var cookieData = JSON.stringify({userId: user.id});
          var encryptedCookieData = encryption.encypher(cookieData);
          res.setHeader('Set-Cookie', ['session=' + encryptedCookieData]);
          res.statusCode = 200;
          res.end('Successful Login :)');
        }
      });
  });
}

/** @function destroy
 * Destroy the memory of this decision from the memory of mankind!!
 */
function destroy(){
  res.setHeader('Set-Cookie', ['']);
  res.statusCode = 200;
  res.end('Logged out successfully! :)');
}

/** @function loginRequired
 * Requires login!
 */
 function loginRequired(req, res, next){
   var session = req.headers.cookie.session;
   var sessionData = encryption.decypher(session);
   var sessionObj = JSON.parse(sessionData);
   if(sessionObj.userId){
     req.userId = sessionObj.userId;
     return next(req, res);
   }else{
     res.statusCode = 403;
     res.end('Authentication required hacker >:(');
   }
 }
