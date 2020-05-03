const mongoose = require('mongoose');
const passportLocalMongoose = require('passport-local-mongoose');

let userSchema = new mongoose.Schema({
    name: String,
    email: String,
    password: {
        type: String,
        // select is false so that no one can see the password in the databse also
        select: false
    },
    resetPasswordToken: String,
    resetPasswordExpires: Date
});

userSchema.plugin(passportLocalMongoose,{usernameField: 'email'});
module.exports = mongoose.model('User', userSchema);