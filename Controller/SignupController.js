'use strict'

const response = require('./../response')
const jwt = require('jsonwebtoken')
const config = require('./../config')
const User = require('./../models/User')
const Confirmation = require('./../models/Confirmation')

exports.confirmPhoneNumber = async (req, res) => {

	try {
		var service = req.query.service
		var phone_number = req.query.phone_number
		if (phone_number && phone_number[0] === '8') phone_number = phone_number.replace('8', '7')
		var ip = req.socket.remoteAddress

		if (!service || !phone_number) return response.error(6, "invalid request", [{ "key": 'service', "value": 'required' }, { "key": 'phone_number', "value": 'required' }], res)
		if (!phone_number.match(/^[0-9]{3,15}$/)) return response.error(7, "invalid parameter value", [{ "key": 'phone_number', "value": phone_number, "regex": '/^[0-9]{3,15}$/' }], res)
		if (await User.findOne({ "phone_number": phone_number })) return response.error(51, "already in use", [{ "key": 'phone_number', "value": phone_number }], res)
		let confirmationFromIP = await Confirmation.findOne({ "ip": ip })
		let confirmationFromPhoneNumber = await Confirmation.findOne({ "phone_number": phone_number })
		if (confirmationFromIP && Date.now() - confirmationFromIP.datetime <= 60000 || confirmationFromPhoneNumber && Date.now() - confirmationFromPhoneNumber.datetime <= 60000) return response.error(5, "too frequent requests", [{ "key": 'left', "value": 60 - (confirmationFromIP && Date.now() - confirmationFromIP.datetime <= 60 ? confirmationFromIP.datetime : confirmationFromPhoneNumber.datetime) + Date.now() }], res)

		var code = Math.round(Math.random() * (9999 - 1000) + 1000)

		import('node-fetch').then(({ "default": fetch }) => {
			fetch(`https://sms.ru/sms/send?api_id=3AC1C1C8-385F-BDBC-5BD8-CBF0748A8CB3&to=${phone_number}&msg=${code} — код для регистрации в сервисе «specter».&json=1`)
			.then(async smsRes => {
				let JSONRes = await smsRes.json()

				if (JSONRes.sms[phone_number].status_code == 202) return response.error(100, "the phone number is incorrect", [{ "key": 'phone_number', "value": phone_number }], res)
				if (JSONRes.sms[phone_number].status_code != 100) return response.systemError(JSONRes.sms[phone_number], res)

				await Confirmation.findOneAndDelete({ "ip": ip })
				await Confirmation.findOneAndDelete({ "phone_number": phone_number })

				let confirmation = await new Confirmation({ "ip": ip, "phone_number": phone_number, "code": code, "datetime": Date.now() }).save()

				let confirm_token = jwt.sign({
					"type": 'confirm_signup',
					"service": service,
					"confirm_id": confirmation._id
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

		if (req.token_payload.type != 'confirm_signup') return response.error(4, "invalid access token", [{ "key": 'Authorization', "value": 'invalid' }], res)
		if (!code) return response.error(6, "invalid request", [{ "key": 'code', "value": 'required' }], res)
		var confirmation = await Confirmation.findOne({ "_id": req.token_payload.confirm_id })
		if (confirmation.code != code) return response.error(101, "invalid confirmation code", [{ "key": 'code', "value": code }], res)

		let signup_token = jwt.sign({
			"type": 'signup',
			"service": req.token_payload.service,
			"phone_number": confirmation.phone_number
		}, config.JWT_SECRET_KEY, { "expiresIn": '30m' })

		return response.send({ "signup_token": `Bearer ${signup_token}` }, res)
	} catch (error) {
		return response.systemError(error, res)
	}

}

exports.signup = async (req, res) => {

	try {
		var password = req.query.password
		var phone_number = req.token_payload.phone_number

		if (req.token_payload.type != 'signup') return response.error(4, "invalid access token", [{ "key": 'Authorization', "value": 'invalid' }], res)
		if (!password) return response.error(6, "invalid request", [{ "key": 'password', "value": 'required' }], res)
		if (!password.match(/^[a-zа-я0-9_.%+@$#!-]{8,128}$/i)) return response.error(7, "invalid parameter value", [{ "key": 'password', "value": password, "regex": '/^[a-zа-я0-9_.%+@$#!-]{8,128}$/i' }], res)
		if (await User.findOne({ "phone_number": phone_number })) return response.error(51, "already in use", [{ "key": 'phone_number', "value": phone_number }], res)

		var ecost_id = await require('./SequenceController').getNextSequence('users')
		await new User({ "id": ecost_id, "phone_number": phone_number, "password": require('password-hash').generate(password) }).save()

		let service_auth_token = jwt.sign({
			"type": 'service_auth',
			"service": req.token_payload.service,
			"ecost_id": ecost_id
		}, config.JWT_SECRET_KEY, { "expiresIn": '30m' })

		return response.send({ "service_auth_token": `Bearer ${service_auth_token}` }, res)
	} catch (error) {
		return response.systemError(error, res)
	}

}