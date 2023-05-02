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
		if (phone_number[0] === '8') phone_number = phone_number.replace('8', '7')
		var password = req.query.password
		var ip = req.socket.remoteAddress

		var user = await User.findOne({ phone_number })
		let confirmationIP = await Confirmation.findOne({ "ip": ip })
		let confirmationPhoneNumber = await Confirmation.findOne({ "phone_number": phone_number })

		if (!service || !phone_number || !password) return response.error(4, "one of the required parameters was not passed", [{ "key": 'service', "value": 'required' }, { "key": 'phone_number', "value": 'required' }, { "key": 'password', "value": 'required' }], res)
		if (!user) return response.error(100, "the user is not registered", [{ "key": 'phone_number', "value": phone_number }], res)
		if (!passwordHash.verify(password, user.password)) return response.error(102, "wrong password", [{ "key": 'password', "value": password }], res)
		if (confirmationIP && Date.now() - confirmationIP.datetime <= 60000 || confirmationPhoneNumber && Date.now() - confirmationPhoneNumber.datetime <= 60000) return response.error(6, "too frequent requests", [{ "key": 'left', "value": 60 - (confirmationIP && Date.now() - confirmationIP.datetime <= 60 ? confirmationIP.datetime : confirmationPhoneNumber.datetime) + Date.now() }], res)

		var code = Math.round(Math.random() * (9999 - 1000) + 1000)

		import('node-fetch').then(({ "default": fetch }) => {
			fetch(`https://sms.ru/sms/send?api_id=3AC1C1C8-385F-BDBC-5BD8-CBF0748A8CB3&to=${phone_number}&msg=${code} — код для входа в сервис «specter».%0A%0AЕсли код отправляли не вы, то срочно смените пароль от аккаунта.&json=1`)
				.then(async smsRes => {
					let JSONRes = await smsRes.json()

					if (!JSONRes.sms || JSONRes.sms[phone_number].status_code != 100) return response.systemError(JSONRes, res)

					await Confirmation.findOneAndDelete({ "ip": ip })
					await Confirmation.findOneAndDelete({ "phone_number": phone_number })

					let confirmation = new Confirmation({ "ip": ip, "phone_number": phone_number, "code": code, "datetime": Date.now() })
					await confirmation.save()

					let confirm_token = jwt.sign({
						"type": 'confirm_signin',
						"service": service,
						"confirm_id": confirmation._id,
						"ecost_id": user._id
					}, config.JWT, { "expiresIn": '5m' })

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
		var service = req.token_payload.service

		var confirmation = await Confirmation.findOne({ "_id": req.token_payload.id })

		if (req.token_payload.type != 'confirm_signin' || !confirmation) {
			let error_details = []
			if (req.token_payload.type != 'confirm_signin') error_details.push({ "key": 'type', "value": req.token_payload.type, "required": 'confirm_signin' })
			if (!confirmation) error_details.push({ "key": 'id', "value": req.token_payload.id })
			return response.error(3, "invalid access token", error_details, res)
		}
		if (!code) return response.error(4, "one of the required parameters was not passed", [{ "key": 'code', "value": 'required' }], res)
		if (confirmation.code != code) return response.error(105, "invalid confirmation code", [{ "key": 'code', "value": code }], res)

		// TODO: ДОДЕЛАТЬ КОГДА БУДЕТ ВОЗМОЖНОСТЬ
		/*let user = service === 'specter' ? await SpecterUser.findOne({ "ecost_id": req.token_payload.ecost_id }) : null

		if (!user) {
			let auth_token = jwt.sign({
				"type": 'service_signup',
				"service": service,
				"id": req.token_payload.ecost_id
			}, config.JWT, { "expiresIn": '30m' })

			return response.send({ "auth_token": `Bearer ${auth_token}` }, res)
		}

		let access_token = jwt.sign({
			"type": 'access',
			"service": service,
			"ecost_id": req.token_payload.ecost_id,
			"specter_id": user._id
		}, config.JWT, { "expiresIn": '540d' })

		return response.send({ "access_token": `Bearer ${access_token}` }, res)*/
	} catch (error) {
		return response.systemError(error, res)
	}

}