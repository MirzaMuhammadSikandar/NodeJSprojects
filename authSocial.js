//Note: code copied from passport.js
require('dotenv').config()
const User = require('./models/user.js')
const passport = require('passport')
const GoogleStrategy = require('passport-google-oauth2').Strategy;
const GithubStrategy = require("passport-github2").Strategy;

//--------------------------------GOOGLE------------------------------------
passport.use(new GoogleStrategy({
  clientID: process.env.GOOGLE_CLIENT_ID,
  clientSecret: process.env.GOOGLE_CLIENT_SECRET,
  callbackURL: "http://localhost:5555/google/callback",
  passReqToCallback: true
},
  async function (request, accessToken, refreshToken, profile, done) {
    // User.findOrCreate({ googleId: profile.id }, function (err, user) {
    //   return done(err, user);
    // });
    // return done(err, profile);

    try {
      const name = `${profile.name.givenName} ${profile.name.familyName}`
      const email = profile.email
      const image = profile.picture
      const responseUser = await User.create({
        name,
        email,
        image
      })

      console.log('User Response GMAIL-------------------', responseUser)
      // console.log('Profile-------------------', name,':', email,':' ,picture)

    } catch (error) {
      // console.log(JSON.stringify(error))
      if (error.code === 11000) {

        //error.code 11000 is for duplication
        return done(null, profile);
      }
      return done(null, profile);
    }

    // console.log('Profile-------------------------', profile.email)
    return done(null, profile);
  }
));


//--------------------------------GIHUB------------------------------------
passport.use(new GithubStrategy(
  {
    clientID: process.env.GITHUB_CLIENT_ID,
    clientSecret: process.env.GITHUB_CLIENT_SECRET,
    callbackURL: "http://localhost:5555/github/callback",
    passReqToCallback: true
  },
  async function (request, accessToken, refreshToken, profile, done) {
    // User.findOrCreate({ googleId: profile.id }, function (err, user) {
    //   return done(err, user);
    // });
    // return done(err, profile);

    try {
      // console.log('GITHUB AUTH--------------------')
      // console.log("Profile Obj-------------------", profile)
      const name = `${profile.displayName}`
      const email = profile.emails[0].value
      const image = profile.photos[0].value
      const responseUser = await User.create({
        name,
        email,
        image
      })

      console.log('User Response GITHUB-------------------', responseUser)
      console.log('Profile-------------------', name,':', email,':' ,image)

    } catch (error) {
      // console.log(JSON.stringify(error))
      if (error.code === 11000) {

        //error.code 11000 is for duplication
        return done(null, profile);
      }
      return done(null, profile);
    }

    // console.log('Profile-------------------------', profile.email)
    return done(null, profile);
  }
));


passport.serializeUser(function (user, done) {
  done(null, user)
})

passport.deserializeUser(function (user, done) {
  done(null, user)
})
