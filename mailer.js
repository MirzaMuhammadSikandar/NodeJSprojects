const nodemailer = require('nodemailer');


//  send mail from my gmail account 
const sendEmail = (user, data, res) => {

    console.log('-------------------->', user.email)

    let config = {
        service: 'gmail',
        auth: {
            user: 'sikandarmiirza@gmail.com',
            pass: 'yhortpsrzknkxnsa'
        }
    }

    let transporter = nodemailer.createTransport(config);

    let message = {
        from: 'sikandarmiirza@gmail.com',
        to: user.email,
        subject: 'Test Email', 
        text: `${data}.` 
    }

    transporter.sendMail(message).then(() => {
        return res.status(201).json({
            msg: "you should receive an OTP on your email"
        })
    }).catch(error => {
        return res.status(500).json({ error })
    })
}


module.exports = {
    sendEmail
}