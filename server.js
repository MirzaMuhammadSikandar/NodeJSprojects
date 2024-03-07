const express = require("express");
const session = require('express-session');
const morgan =require("morgan")
const cors = require('cors')
const { PORT, mongoDBURL } = require("./database/config.js");
const { checkConnection } = require("./database/connection.js");
const appRoute = require("./routes/userRoute.js")
require('./authSocial.js')
const passport = require('passport');
const { isLoggedIn } = require('./middleware/auth.js')
const {generateAccessToken} = require('./helperFunctions.js')

const app = express()

//---- Middleware for parsing request body ---- 
app.use(express.json());
app.use(morgan('dev'))
app.use(cors());
app.use(session({ secret: 'cats', resave: false, saveUninitialized: true }));
app.use(passport.initialize());
app.use(passport.session());


app.use('/user', appRoute);

//static Images Folder
app.use('/Images', express.static('./Images'))


// app.get('/', (request, response) => {
//     response.send('<a href="/user/auth/google">Authenticate with Google</a><br><a href="/user/auth/github">Authenticate with Github</a>');
// });

app.get('/', (request, response) => {
    response.send('<a href="/auth/google">Authenticate with Google</a><br><a href="/auth/github">Authenticate with Github</a>');
});


//-----------------------------------------GOOGLE--------------------------------------------
const CLIENT_URL= "http://localhost:3001/"
const FAIL_URL="http://localhost:3001/"

app.get('/auth/google',
    passport.authenticate('google', { scope: ['email', 'profile'] }
    ));

app.get('/google/callback',
passport.authenticate('google', {
        successRedirect: '/protected',
        failureRedirect: '/auth/failure'
    })
);


//-----------------------------------------GITHUB--------------------------------------------

app.get('/auth/github',
    passport.authenticate('github', { scope: ['profile'] }
    ));

app.get('/github/callback',
    passport.authenticate('github', {
        successRedirect: '/protected',
        failureRedirect: '/auth/failure'
    })
)


app.get('/protected', isLoggedIn, (req, res) => {
    console.log("---------------------------", req.user.emails[0].value)
    console.log("---------------------------", req.user.id)
// `,imkujnhybgvfdcs//?${tpken}`  
    const accessToken = generateAccessToken(req.user.id, req.user.emails[0].value)
    // const refreshToken = generateRefreshToken(user._id, user.email)
    // refreshTokens.push(refreshToken)
    // return response.json({ accessToken: accessToken, userEmail: user.email, userPassword: user.password})
    // res.json({accessToken: accessToken});
    // console.log('res-------------------', res)
    const redirectUrl = `${CLIENT_URL}?token=${accessToken}`;
    console.log('redirectURL---------------------', redirectUrl)
    res.redirect(redirectUrl);

});

app.get('/logout', (req, res) => {
    req.logout();
    req.session.destroy();
    res.send('Goodbye!');
});

app.get('/auth/failure', (req, res) => {
    // res.send('Failed to authenticate..');
    const redirectUrl = `${FAIL_URL}?error=loginError`;
    res.redirect(redirectUrl);
});

//----------------MongoDB Connection-------------------
checkConnection(app, PORT, mongoDBURL);


// http://localhost:3000/google/callback?code=4%2F0AeaYSHAkwkoUzsop4PePnQNCr6JadvIsBigVZaUiK5AXGixScTFEGJvcEba8a1PwBaNI9w&scope=email+profile+https%3A%2F%2Fwww.googleapis.com%2Fauth%2Fuserinfo.email+https%3A%2F%2Fwww.googleapis.com%2Fauth%2Fuserinfo.profile+openid&authuser=0&prompt=consent