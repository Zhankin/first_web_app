var express = require('express');
var passport = require('passport');
var Strategy = require('passport-local').Strategy;
var db = require('./db');
var fs = require('fs');
var https = require('https');
const socketIO = require('socket.io');
const r = require('rethinkdb');
const config = require('./config.json');

var privateKey  = fs.readFileSync('/etc/letsencrypt/live/alma-cup.com/privkey.pem', 'utf8');
var certificate = fs.readFileSync('/etc/letsencrypt/live/alma-cup.com/cert.pem', 'utf8');
var credentials = {key: privateKey, cert: certificate};

const db1 = Object.assign(config.rethinkdb, {
   db: 'db1_tennis'
});


// Configure the local strategy for use by Passport.
//
// The local strategy require a `verify` function which receives the credentials
// (`username` and `password`) submitted by the user.  The function must verify
// that the password is correct and then invoke `cb` with a user object, which
// will be set at `req.user` in route handlers after authentication.
passport.use(new Strategy(
  function(username, password, cb) {
    db.users.findByUsername(username, function(err, user) {
      if (err) { return cb(err); }
      if (!user) { return cb(null, false); }
      if (user.password != password) { return cb(null, false); }
      return cb(null, user);
    });
  }));


// Configure Passport authenticated session persistence.
//
// In order to restore authentication state across HTTP requests, Passport needs
// to serialize users into and deserialize users out of the session.  The
// typical implementation of this is as simple as supplying the user ID when
// serializing, and querying the user record by ID from the database when
// deserializing.
passport.serializeUser(function(user, cb) {
  cb(null, user.id);
});

passport.deserializeUser(function(id, cb) {
  db.users.findById(id, function (err, user) {
    if (err) { return cb(err); }
    cb(null, user);
  });
});




// Create a new Express application.
var app = express();

// Configure view engine to render EJS templates.
app.set('views', __dirname + '/views');
app.set('view engine', 'ejs');

// Use application-level middleware for common functionality, including
// logging, parsing, and session handling.
app.use(require('morgan')('combined'));
app.use(require('cookie-parser')());
app.use(require('body-parser').urlencoded({ extended: true }));
app.use(require('express-session')({ secret: 'keyboard cat', resave: false, saveUninitialized: false }));

// Initialize Passport and restore authentication state, if any, from the
// session.
app.use(passport.initialize());
app.use(passport.session());

// Define routes.
app.get('/',
  function(req, res) {
    res.render('home', { user: req.user });
  });

app.get('/login',
  function(req, res){
    res.render('login');
  });
  
app.post('/login', 
  passport.authenticate('local', { failureRedirect: '/login' }),
  function(req, res) {
    res.redirect('/');
  });
  
app.get('/logout',
  function(req, res){
    req.logout();
    res.redirect('/');
  });

app.get('/profile',
  require('connect-ensure-login').ensureLoggedIn(),
  function(req, res){
    res.render('profile', { user: req.user });
  });

//app.listen(3000);

//Redirect from 80->443/////////
var http = require('http');
http.createServer(function (req, res) {
    res.writeHead(301, { "Location": "https://" + req.headers['host'] + req.url });
    res.end();
}).listen(80);
////////////////////////////////


var httpsServer = https.createServer(credentials, app);
var server=httpsServer.listen(443);


const io = socketIO(server)

r.connect(db1)
    .then(conn => {
        // The changefeed is provided by change() function
        // which emits broadcast of new messages for all clients
        r.table('table1')
            .changes()
            .run(conn)
            .then(cursor => {
                cursor.each((err, data) => {
                    const message = data.new_val;
                    io.sockets.emit('/update', message);
                });
            });
        // Listing all messages when new user connects into socket.io
        io.on('connection', (client) => {
            r.table('table1')
                .run(conn)
                .then(cursor => {
                    cursor.each((err, message) => {
                        io.sockets.emit('/update', message);
                    });
                });
	client.on('/update', (body) => {
                const {
                    command1_name,command1_score,command2_name,command2_score
                } = body;
                const data = {
                    command1_name,command1_score,command2_name,command2_score
                };
		r.table('table1').filter(
			r.row('command1_name').eq(command1_name).and(
			r.row('command2_name').eq(command2_name))
			).update(data).run(conn);
                //r.table('table1').insert(data).run(conn);
            });
        });
});

