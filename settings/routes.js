'use strict'

module.exports = (app) => {

	const tokenController = require('./../Controller/TokenController')
	const signupController = require('./../Controller/SignupController')
	const signinController = require('./../Controller/SigninController')
	const passwordResetController = require('./../Controller/PasswordResetController')

	app.all('*', (req, res, next) => {
		if (!req.query.v) return require('./../response').error(4, "one of the required parameters was not passed", [{ "key": 'v', "value": 'required' }], res)
		return next()
	})

	//	auth / signup
	app.route('/api/auth/method/signup.confirmPhoneNumber').get(signupController.confirmPhoneNumber)
	app.route('/api/auth/method/signup.checkConfirmCode').get(tokenController.control, signupController.checkConfirmCode)
	app.route('/api/auth/method/signup').get(tokenController.control, signupController.signup)

	// auth / signin
	//app.route('/api/auth/method/signin').get(signinController.signin)
	//app.route('/api/auth/method/signin.checkConfirmCode').get(tokenController.control, signinController.checkConfirmCode)

	// auth / passwordReset
	//app.route('/api/auth/method/passwordReset.confirmPhoneNumber').get(passwordResetController.confirmPhoneNumber)
	//app.route('/api/auth/method/passwordReset.checkConfirmCode').get(tokenController.control, passwordResetController.checkConfirmCode)
	//app.route('/api/auth/method/passwordReset').get(tokenController.control, passwordResetController.passwordReset)

}