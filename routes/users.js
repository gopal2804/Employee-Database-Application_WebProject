const express = require('express');
const router = express.Router();
const passport = require('passport');
const crypto = require('crypto');
const async = require('async');
const nodemailer = require('nodemailer');
const mongoose = require('mongoose');

// requiring user model
const User = require('../models/usermodel');

let employeeSchema = new mongoose.Schema({
    name: String,
    designation: String,
    salary: Number
});
let Employee = mongoose.model('Employee', employeeSchema);

// checks if user is authenticated
function isAuthenticatedUser(req,res,next){
    if(req.isAuthenticated()){
        return next();
    }
    req.flash('error_msg',"Plese login first to access this page");
    res.redirect('/login');
}

// get routes
router.get('/',(req,res)=>{
    res.redirect('/login')
});


router.get('/login',(req,res)=>{
    res.render('login');
});


router.get('/signup',(req,res)=>{
    res.render('signup');
});

router.get('/dashboard',isAuthenticatedUser,(req,res)=>{
    Employee.find({}, (error, employee) => {
        if (error) {
            req.flash('error_msg', 'ERROR:' + error);
            res.redirect('/dashboard');
        } else {
            res.render('dashboard', { employee: employee });
        }
    });

});

router.get('/logout',(req,res)=>{
    req.logOut();
    req.flash('success_msg','you have been logged out');
    res.redirect('/login');
});

router.get('/forgot',(req,res)=>{
    res.render('forgot');
});

router.get('/reset/:token',(req,res)=>{
    User.findOne({resetPasswordToken: req.params.token, resetPasswordExpires: {$gt: Date.now()}})
        .then(user=>{
            if(!user){
                req.flash('error_msg','Password reset token is invalid or has been expired');
                res.redirect('/forgot');
            }

            res.render('newpassword',{token: req.params.token});
        })
        .catch(err=>{
            req.flash('error_msg','ERROR:'+err);
            res.redirect('/forgot');
        });
});

router.get('/password/change',isAuthenticatedUser,(req,res)=>{
    res.render('changepassword');
});

router.get('/employee/new',isAuthenticatedUser, (req, res) => {
    res.render('new');
});

router.get('/employee/search',isAuthenticatedUser,(req,res)=>{
    res.render('search',{ searchQuery: '' });
});

router.get('/employee',isAuthenticatedUser, (req, res) => {
    let searchQuery = { name: req.query.name };
    Employee.findOne(searchQuery, (error, searchQuery) => {
        if (error) {
            req.flash('error_msg', 'ERROR:' + error);
            res.redirect('/dasboard');
        } else {
            res.render('search', { searchQuery: searchQuery });
        }
    });

});

router.get('/edit/:id',isAuthenticatedUser, (req, res) => {
    let searchQuery = { _id: req.params.id };
    Employee.findOne(searchQuery, (error, employee) => {
        if (error) {
            req.flash('error_msg', 'ERROR:' + error);
            res.redirect('/dashboard');
        } else {
            res.render('edit', { employee: employee });
        }
    });
});


router.get("/deleteAll",isAuthenticatedUser, (req, res) => {
    Employee.deleteMany({}, (error) => {
        if (error) {
            req.flash('error_msg', 'ERROR:' + error);
            res.redirect('/dashboard');
        } else {
            req.flash('success_msg', 'All data from the database deleted successfully');
            res.redirect('/dashboard');
        }
    });
});


// post routes
router.post('/login', passport.authenticate('local',{
    successRedirect: '/dashboard',
    failureRedirect: '/login',
    failureFlash: 'Invalid email or password . Try again !'
}));

router.post('/signup',(req,res)=>{
    let {name, email, password} = req.body;

    let userData= {
        name: name,
        email: email
    };
    // like this the password will be stores in hash format
    User.register(userData,password, (error,user)=>{
        if(error){
            req.flash('error_msg', 'ERROR:'+error);
            res.redirect('/signup');
        }
        passport.authenticate('local') (req,res,()=>{
            req.flash('success_msg','Account created successfully');
            res.redirect('/login');
        });
    });

});

// routes to handle forgot password
router.post('/forgot',(req,res,next)=>{
    let recoveryPassword = '';
    // this method is used to run the functions one after the other 
    // basically here we pass the array of the functios
    async.waterfall([
        (done)=>{
            // generating token for the user
            crypto.randomBytes(20,(err,buf)=>{
                let token = buf.toString('hex');
                done(err,token);
            });
        },
        (token,done)=>{
            User.findOne({email: req.body.email})
                .then(user=>{
                    if(!user){
                        req.flash('error_msg','User does not exist with this email address');
                        return res.redirect('/forgot');
                    }

                    user.resetPasswordToken = token;
                    user.resetPasswordExpires = Date.now() + 1800000; //which means after 30 minutes the link will be expired for reset password

                    user.save(err=>{
                        done(err,token,user);
                    });
                })
                .catch(err=>{
                    req.flash('error_msg','ERROR:'+err);
                    res.redirect('/forgot');
                });
        },
        (token,user)=>{
                // NOW sending mail using smtp and nodemailer package
            let smtp = nodemailer.createTransport({
                service: 'Gmail',
                auth: {
                    user: process.env.GMAIL_EMAIL,
                    pass: process.env.GMAIL_PASSWORD
                }
            });

            let mailOptions = {
                to: user.email,
                from: 'Gopal Gupta webproject2804@gmail.com',
                subject: 'Password Recovery Email',
                text: 'Please click the following link to recover your password: \n\n'+
                        'http://'+req.headers.host+'/reset/'+token+'\n\n'+
                        'If you did not request this , please ignore this email.'
            };
            smtp.sendMail(mailOptions,err=>{
                req.flash('success_msg','Email send with furthur instructions. Please check that');
                res.redirect('/forgot');
            });
        }

    ],err=>{
        if(err){
            res.redirect('/forgot');
        }
    });
});

router.post('/reset/:token', (req,res)=>{
    async.waterfall([
        (done)=>{
            User.findOne({resetPasswordToken: req.params.token, resetPasswordExpires: {$gt: Date.now()}})
                .then(user=>{
                    if(!user){
                        req.flash('error_msg','Password reset token is invalid or has been expired');
                        res.redirect('/forgot');
                    }

                    if(req.body.password!==req.body.confirmpassword){
                        req.flash('error_msg','Password does not match');
                        return res.redirect('/forgot');
                    }

                    user.setPassword(req.body.password,err=>{
                        user.resetPasswordToken= undefined;
                        user.resetPasswordExpires= undefined;

                        user.save(err=>{
                            req.logIn(user,err=>{
                                done(err,user);
                            });
                        });
                    });
                })
                .catch(err=>{
                    req.flash('error_msg','ERROR:'+err);
                    res.redirect('/forgot');
                });
        },

        // now sending the email to user that the password is changed successfully
        (user)=>{
            let smtp= nodemailer.createTransport({
                service: 'Gmail',
                auth: {
                    user: process.env.GMAIL_EMAIL,
                    pass: process.env.GMAIL_PASSWORD
                }
            });
            let mailOptions={
                to: user.email,
                from: "Gopal Gupta webproject2804@gmail.com",
                subject: 'Your password is changed',
                text: 'Hello, '+user.name+'\n\n'+
                        'This is the confirmation that the password for your account '+user.email+' has been changed'
            };

            smtp.sendMail(mailOptions, err=>{
                req.flash('success_msg',"Your password has been changed successfully");
                res.redirect('/login');
            });
        }
    ],err=>{
        res.redirect('/login');
    });
});

router.post('/password/change',(req,res)=>{
    if(req.body.password!=req.body.confirmpassword){
        req.flash('error_msg',"Password does not match, Type again");
        return res.redirect('/password/change');
    }
    User.findOne({email: req.user.email})
        .then(user=>{
            user.setPassword(req.body.password,err=>{
                user.save()
                    .then(user=>{
                            req.flash('success_msg','Password changed successfully');
                            res.redirect('/dashboard');
                    })
                    .catch(err=>{
                        req.flash('error_msg','ERROR:'+err);
                        res.redirect('/password/change');
                    });
            });
        })

});

router.post('/employee/new', (req, res) => {
    let newEmployee = {
        name: req.body.name,
        designation: req.body.designation,
        salary: req.body.salary
    };
    Employee.create(newEmployee, (error, newEmployee) => {
        if (error) {
            req.flash('error_msg', 'ERROR:' + error);
            res.redirect('/dashboard');
        } else {
            req.flash('success_msg', 'Employee data added to database successfully.');
            res.redirect('/dashboard');
        }
    });
});

router.put('/edit/:id', (req, res) => {
    let searchQuery = { _id: req.params.id };
    Employee.updateOne(searchQuery, {
        $set: {
            name: req.body.name,
            designation: req.body.designation,
            salary: req.body.salary
        }
    })
        .then(employee => {
            req.flash('success_msg', 'Employee data updated successfully.');
            res.redirect('/dashboard');
        })
        .catch(err => {
            req.flash('error_msg', 'ERROR:' + error);
            res.redirect('/dashboard');
        });
});

router.delete("/delete/:id", (req, res) => {
    let searchQuery = { _id: req.params.id };

    Employee.deleteOne(searchQuery, (error, employee) => {
        if (error) {
            req.flash('error_msg', 'ERROR:' + error);
            res.redirect('/dashboard');
        } else {
            req.flash('success_msg', 'Employee deleted successfully.');
            res.redirect('/dashboard');
        }
    });
});

module.exports = router;