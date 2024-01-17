import passport from "passport";
import LocalStrategy from 'passport-local'
import GitHubStrategy from 'passport-github2'
import userModel from "../dao/models/userModel";
import bcrypt from 'bcrypt'

passport.use(new LocalStrategy({
    usernameField: 'email',
    passwordField: 'password'
}, async (email, password, done) => {
    try {
        const user = await userModel.findOne({ email })
        if(!user) return done(null, false, { message: 'Usuario no encontrado' })

        const validPassword = await bcrypt.compare(password, user.password)
        if (!validPassword) return done(null, false, { message: 'Contraseña incorrecta' })

        return done(null, user)
    } catch (error) {
        return done(error)
    }
}));

passport.use(new GitHubStrategy({
    clientID: process.env.GITHUB_CLIENT_ID,
    clientSecret: process.env.GITHUB_CLIENT_SECRET,
    callbackURL: 'http://localhost:8080/api/sessions/github/callback'
}, async (accessToken, refreshToken, profile, done) => {
    try {
        const existUser = await userModel.findOne({ githubId: profile.id })
        if(existUser) return done(null, existUser)

        const newUser = await userModel.create({
            githubId: profile.id,
            first_name: profile.displayName,
            email: profile.emails[0].value,
            password: 'generatedGitHubPassword'
        })
        return done(null, newUser)

    } catch (error) {
        return done(error)
    }
}));

passport.serializeUser((user, done) => {
    done(null, user.id)
});

passport.deserializeUser(async (id, done) => {
    try {
        const user = await userModel.findById(id)
        done(null, user)
    } catch (error) {
        done(error)
    }
})

export default passportConfig