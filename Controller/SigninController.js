'use strict'

const response = require('./../response')
const jwt = require('jsonwebtoken')
const config = require('./../config')
const passwordHash = require('password-hash')
const User = require('./../models/User')
const Confirmation = require('./../models/Confirmation')

exports.signin = async (req, res) => {

	try {
		var service = req.query.service
		var phone_number = req.query.phone_number
		if (phone_number && phone_number[0] === '8') phone_number = phone_number.replace('8', '7')
		var password = req.query.password
		var ip = req.socket.remoteAddress

		if (!service || !phone_number || !password) return response.error(6, "invalid request", [{ "key": 'service', "value": 'required' }, { "key": 'phone_number', "value": 'required' }, { "key": 'password', "value": 'required' }], res)
		var user = await User.findOne({ "phone_number": phone_number }, "-_id id password")
		if (!user) return response.error(50, "not exist", [{ "key": 'phone_number', "value": phone_number }], res)
		if (!passwordHash.verify(password, user.password)) return response.error(200, "wrong password", [{ "key": 'password', "value": password }], res)
		let confirmationFromIP = await Confirmation.findOne({ "ip": ip })
		let confirmationFromPhoneNumber = await Confirmation.findOne({ "phone_number": phone_number })
		if (confirmationFromIP && Date.now() - confirmationFromIP.datetime <= 60000 || confirmationFromPhoneNumber && Date.now() - confirmationFromPhoneNumber.datetime <= 60000) return response.error(5, "too frequent requests", [{ "key": 'left', "value": 60 - (confirmationFromIP && Date.now() - confirmationFromIP.datetime <= 60 ? confirmationFromIP.datetime : confirmationFromPhoneNumber.datetime) + Date.now() }], res)

		var code = Math.round(Math.random() * (9999 - 1000) + 1000)

		import('node-fetch').then(({ "default": fetch }) => {
			fetch(`https://sms.ru/sms/send?api_id=3AC1C1C8-385F-BDBC-5BD8-CBF0748A8CB3&to=${phone_number}&msg=${code} — код для входа в сервис «specter».%0A%0AЕсли код отправляли не вы, то срочно смените пароль от аккаунта.&json=1`)
			.then(async smsRes => {
				let JSONRes = await smsRes.json()

				if (!JSONRes.sms || JSONRes.sms[phone_number].status_code != 100) return response.systemError(JSONRes, res)

				await Confirmation.findOneAndDelete({ "ip": ip })
				await Confirmation.findOneAndDelete({ "phone_number": phone_number })

				let confirmation = await new Confirmation({ "ip": ip, "phone_number": phone_number, "code": code, "datetime": Date.now() }).save()

				let confirm_token = jwt.sign({
					"type": 'confirm_signin',
					"service": service,
					"confirm_id": confirmation._id,
					"ecost_id": user.id
				}, config.JWT_SECRET_KEY, { "expiresIn": '5m' })

				return response.send({ "confirm_token": `Bearer ${confirm_token}` }, res)
			})
			.catch(error => {
				return response.systemError(error, res)
			})
		})
	} catch (error) {
		return response.systemError(error, res)
	}

}

exports.checkConfirmCode = async (req, res) => {

	try {
		var code = req.query.code

		if (req.token_payload.type != 'confirm_signin') return response.error(4, "invalid access token", [{ "key": 'Authorization', "value": 'invalid' }], res)
		if (!code) return response.error(6, "invalid request", [{ "key": 'code', "value": 'required' }], res)
		if ((await Confirmation.findOne({ "_id": req.token_payload.confirm_id })).code != code) return response.error(101, "invalid confirmation code", [{ "key": 'code', "value": code }], res)

		import('node-fetch').then(({ "default": fetch }) => {
			fetch(`http:///213.219.214.94:3501/api/method/users.getUserId?v=1.0&ecost_id=${req.token_payload.ecost_id}`)
			.then(async serviceRes => {
				let JSONRes = await serviceRes.json()

				if (!JSONRes.res) {
					let auth_token = jwt.sign({
						"type": 'service_signup',
						"service": req.token_payload.service,
						"ecost_id": req.token_payload.ecost_id
					}, config.JWT_SECRET_KEY, { "expiresIn": '30m' })

					return response.send({ "auth_token": `Bearer ${auth_token}` }, res)
				} else {
					let access_token = jwt.sign({
						"type": 'access',
						"service": req.token_payload.service,
						"ecost_id": req.token_payload.ecost_id,
						"service_id": 2
					}, config.JWT_SECRET_KEY, { "expiresIn": '540d' })

					return response.send({ "access_token": `Bearer ${access_token}` }, res)
				}
			})
			.catch(error => {
				return response.systemError(error, res)
			})
		})
	} catch (error) {
		return response.systemError(error, res)
	}

}