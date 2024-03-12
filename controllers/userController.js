require('dotenv').config()
const { sendEmail } = require("../mailer.js")
const crypto = require('crypto');
const jwt = require('jsonwebtoken')
const User = require("../models/user.js")
const { generateAccessToken, generateRefreshToken, generateOTP } = require('../helperFunctions.js')
// require('../authSocial.js')
// const passport = require('passport');

const nameRegex = /^([a-zA-Z]+|[a-zA-Z]+ [a-zA-Z]+)$/
const emailRegex = /^[^\s]+@(gmail|cherrybyte|yahoo)\.com$/;
const passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)[a-zA-Z\d]{8,}$/;
const dateRegex = /^\d{1,2}\/\d{1,2}\/\d{2,4}$/;
const addressRegex = /^(?![ -.&,_'":?!/])(?!.*[- &_'":]$)(?!.*[-.#@&,:?!/]{2})[a-zA-Z0-9- .#@&,_'":.?!/]+$/;


// let refreshTokens = []

//----------------------- Registration -----------------------
const registration = async (request, response) => {
    const { name, email, password: plainTextPassword, dateofbirth, address } = request.body;
    console.log("req.body", request.body);
    if (!email || !plainTextPassword || !name || !dateofbirth || !address || typeof email !== 'string' || typeof plainTextPassword !== 'string' || typeof name !== 'string' || typeof dateofbirth !== 'string' || typeof address !== 'string') {
        return response.json({ status: 'error', error: 'User Input Error' });
    }

    //Name Validation
    // if (!nameRegex.test(name)) {
    //     return response.json({ status: 'error', error: 'Invalid name format' });
    // }

    //Email Validation
    // if (!emailRegex.test(email)) {
    //     return response.json({ status: 'error', error: 'Invalid email format' });
    // }

    //Password Validation
    // if (!passwordRegex.test(plainTextPassword)) {
    //     return response.json({ status: 'error', error: 'Invalid password format' });
    // }

    //DateOfBirth Validation
    // if (!dateRegex.test(dateofbirth)) {
    //     return response.json({ status: 'error', error: 'Invalid date format' });
    // }

    //Address Validation
    // if (!addressRegex.test(address)) {
    //     return response.json({ status: 'error', error: 'Invalid address format' });
    // }

    // Hashing Password
    const password = crypto.createHash('sha256').update(plainTextPassword).digest('hex');
    // console.log("password", password)
    let image;
    if (request.file) {
        image = request.file.filename;
        // console.log("image-------->", image)
    }
    // console.log("req-----------------", request.file.filename)

    try {
        console.log("inside try block")
        const responseUser = await User.create({
            name,
            email,
            password,
            dateofbirth,
            address,
            image,
            otp: generateOTP()
        })
        console.log("ResponseUser----------------", responseUser)

        // if (responseUser && responseUser.verified == false) {
        //     //----------------------- Send OTP via Email -------
        //     try {

        //         return sendEmail(responseUser, responseUser.otp, response)

        //     } catch (error) {
        //         console.error('Error!!!---------------:', error);
        //         return response.json({ status: 'error', error: 'Something went wrong' });
        //     }
        // }

    } catch (error) {
        // console.log(JSON.stringify(error))
        if (error.code === 11000) {

            //error.code 11000 is for duplication
            return response.json({ status: 'error', error: 'email already in use' })
        }
        console.log('Error---------------------------', error)
        return response.json({ status: 'error', Error: error })
    }

    return response.status(200).send('Registration Successful');
}

//----------------------- Login -----------------------
const login = async (request, response) => {
    try {
        const { email, password } = request.body

        console.log("Request----------", request.body)
        const user = await User.findOne({ email }).lean()

        //lean: returns js object

        if (!user) {
            // return response.json({ status: 'error', error: 'Record NOT Found' });
            return response.status(200).send('Record NOT Found');
        }

        // Hash the provided password 
        const passwordHash = crypto.createHash('sha256').update(password).digest('hex');

        // Compare hashed passwords(userinput password and database password)
        if (passwordHash == user.password) {
            // if(user.verified == false)
            // {   
            //     return sendEmail(user, user.otp, response)
            //     // return response.json({ Message: 'Sorry, user is NOT verfied. OTP has been sent to your Email.'});
            // }
            const accessToken = generateAccessToken(user._id, user.email)
            // const refreshToken = generateRefreshToken(user._id, user.email)
            // refreshTokens.push(refreshToken)
            return response.json({ accessToken: accessToken, userEmail: user.email })
        }
        if (request.headers) {
            console.log('header----------------', request.headers)
        }
        return response.json({ status: 'error', error: 'Invalid Password' });
    } catch (error) {
        console.log('Error---------------------------', error)
        return response.json({ status: 'error' })
    }
}


//----------------------- Update User -----------------------
const updateuser = async (request, response) => {
    // console.log("User-----------------", request.body);

    try {
        const { newName, newEmail, newPassword: plainTextPassword, newDateofbirth, newAddress } = request.body;
        // const {newPassword} = request.body;
        const user = request.user
        // console.log("User -----------------", request.user);
        console.log("body ---------------", request.body)
        // console.log("new ---------------", newPassword)
        if (user) {
            if (!newEmail || !plainTextPassword || !newName || !newDateofbirth || !newAddress || typeof newEmail !== 'string' || typeof plainTextPassword !== 'string' || typeof newName !== 'string' || typeof newDateofbirth !== 'string' || typeof newAddress !== 'string') {
                return response.json({ status: 'error', error: 'User Input Error' });
            }
            console.log("User inside if-----------------", request.user);

            //Name Validation
            // if (!nameRegex.test(newName)) {
            //     return response.json({ status: 'error', error: 'Invalid name format' });
            // }

            //Email Validation
            // if (!emailRegex.test(newEmail)) {
            //     return response.json({ status: 'error', error: 'Invalid email format' });
            // }

            //Password Validation
            // if (!passwordRegex.test(plainTextPassword)) {
            //     return response.json({ status: 'error', error: 'Invalid password format' });
            // }

            //DateOfBirth Validation
            // if (!dateRegex.test(newDateofbirth)) {
            //     return response.json({ status: 'error', error: 'Invalid date format' });
            // }

            //Address Validation
            // if (!addressRegex.test(newAddress)) {
            //     return response.json({ status: 'error', error: 'Invalid address format' });
            // }

            const passwordHash = crypto.createHash('sha256').update(plainTextPassword).digest('hex');

            let newImage;
            if (request.file) {
                newImage = request.file.filename;
                // console.log("image-------->", image)
            }
            // console.log('user-------------', user)
            // console.log("User req body-----------------", request.body);
            const userData = await User.findByIdAndUpdate({ _id: user.id }, {
                $set: {
                    name: newName,
                    email: newEmail,
                    password: passwordHash,
                    dateofbirth: newDateofbirth,
                    address: newAddress,
                    image: newImage
                }
            })
            console.log('userData---------------->', userData)
            return response.json({ status: 'ok', message: 'User Data Sucessfully Updated!!!' })
        }
        else {
            return response.json({ status: 'error', error: 'User not found' });
        }
    } catch (error) {
        // console.error('Error!!!---------------:', error);
        return response.json({ status: 'error', error: 'Something went wrong' });
    }
}

//----------------------- forget Password -----------------------
const forgetPassword = async (request, response) => {
    try {
        const { email } = request.body;
        console.log('Forget Password User Email----------------', email);
        const user = await User.findOne({ email });

        console.log('Forget Password----------------', user);

        if (user) {
            const secret = process.env.FORGETPASSWORD_TOKEN_SECRET;
            const payload = {
                id: user._id,
                email: user.email
            }
            const token = jwt.sign(payload, secret, { expiresIn: '15m' })
            // const link = `http://localhost:3000/user/reset-password/${user._id}/${token}`
            const link = `http://localhost:3001/resetpassword?token=${token}`
            console.log(link)
            return sendEmail(user, link, response)
        }
        else {
            return response.json({ status: 'error', error: 'User NOT found' });
        }

    } catch (error) {
        console.error('Error!!!---------------:', error);
        return response.json({ status: 'error', error: 'Something went wrong' });
    }
}


//----------------------- Reset Password -----------------------
const resetPassword = async (request, response) => {
    try {
        console.log('RESET---------------------------------')
        // const _id = request.params.id;
        // const token = request.params.token;
        // const user = await User.findOne({ _id });
        const newPassword = request.body.newpassword;
        console.log('request id--------------------', request.user.id)
        const user = await User.findById({ _id: request.user.id });

        if (user) {
            // const secret = process.env.FORGETPASSWORD_TOKEN_SECRET;
            try {
                // const payload = jwt.verify(token, secret)

                if (!newPassword || typeof newPassword !== 'string') {
                    return response.json({ status: 'error', error: 'User Input Error' });
                }

                // if (!passwordRegex.test(newPassword)) {
                //     return response.json({ status: 'error', error: 'Invalid password format' });
                // }

                const passwordHash = crypto.createHash('sha256').update(newPassword).digest('hex');

                if (passwordHash == user.password) {
                    return response.json({ status: 'error', error: 'Add new Password... This Password already exists!!!' });
                }
                console.log('user id -----------------', user.id)
                const userData = await User.findByIdAndUpdate({ _id: user.id }, { $set: { password: passwordHash } })
                return response.json({ status: 'ok', message: 'Password Reset Completed' })
            } catch (error) {
                return response.json({ status: 'error', error: 'Token Invalid!!!' });
            }
        }
        else {
            return response.json({ status: 'error', error: 'User not found' });
        }

    } catch (error) {
        console.error('Error!!!---------------:', error);
        return response.json({ status: 'error', error: 'Something went wrong' });
    }
}

//----------------------- Get USER -----------------------
const getUser = async (request, response) => {
    try {
        console.log('GET USER _____ request id--------------------', request.user.id)
        const userData = await User.findById({ _id: request.user.id });
        // const decryptedPassword = crypto.createHash('sha256').update(userData.password).digest('hex');
        // console.log('DECRYPTPASSWORD--------------',decryptedPassword)
        console.log('user--------------------', userData)
        return response.json([{ user: userData }]);
    } catch (error) {
        console.error('Error!!!---------------:', error);
        return response.json({ status: 'error', error: 'Something went wrong' });
    }
}

//----------------------- user input OTP Verify -------
const verifyOTP = async (request, response) => {
    try {
        const { email, otp } = request.body;

        const user = await User.findOne({ email });

        if (!user) {
            return response.json({ status: 'error', error: 'User not found' });
        }

        if (user.otp !== otp) {
            return response.json({ status: 'error', error: 'Invalid OTP' });
        }

        if(user.verified == true)
        {
            return response.json({ message: 'User already Verified' });
        }
        let verify = true;

        const userData = await User.findByIdAndUpdate({ _id: user.id }, {
            $set: {
                verified: verify
            }
        })

        return response.json({ status: 'success', message: 'OTP verification successful' });
    } catch (error) {
        console.error('Error verifying OTP:', error);
        return response.json({ status: 'error', error: 'Something went wrong' });
    }
}


// //----------------------- google Login -----------------------
// const googleLogin = (request, response) => {
//     console.log('Google--------------------------')
//     passport.authenticate('google', { scope: ['email', 'profile'] })
// }

// //----------------------- google Call Back -----------------------
// const googleCallBack = (request, response) => {
//     console.log('Google callback--------------------------')
//     passport.authenticate('google', {
//         successRedirect: '/protected',
//         failureRedirect: '/auth/failure'
//     })
// }

// //----------------------- Protected -----------------------
// const protected = (request, response) => {
//     // console.log("---------------------------", req.user.emails[0].value)
//     // console.log("---------------------------", req.user.id)
//     console.log('Protected callback--------------------------')
//     res.send(`Hello ${req.user.displayName}`);
// }

// //----------------------- Failure -----------------------
// const failure = (request, response) => {
//     res.send('Failed to authenticate..');
// }

module.exports = {
    registration,
    login,
    updateuser,
    forgetPassword,
    resetPassword,
    getUser,
    verifyOTP
    // googleLogin,
    // googleCallBack,
    // protected,
    // failure
}