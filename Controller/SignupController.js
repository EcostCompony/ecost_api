'use strict'

const response = require('./../response')
const jwt = require('jsonwebtoken')
const config = require('./../config')
const passwordHash = require('password-hash')
const User = require('./../models/User')
const Confirmation = require('./../models/Confirmation')

exports.confirmPhoneNumber = async (req, res) => {

	try {
		var service = req.query.service
		var phone_number = req.query.phone_number
		if (phone_number[0] === '8') phone_number = phone_number.replace('8', '7')
		var ip = req.socket.remoteAddress

		let confirmationIP = await Confirmation.findOne({ "ip": ip })
		let confirmationPhoneNumber = await Confirmation.findOne({ "phone_number": phone_number })

		if (!service || !phone_number) return response.error(4, "one of the required parameters was not passed", [{ "key": 'service', "value": 'required' }, { "key": 'phone_number', "value": 'required' }], res)
		if (!phone_number.match(/^[0-9]{3,15}$/)) return response.error(5, "invalid parameter value", [{ "key": 'phone_number', "value": phone_number, "regexp": '/^[0-9]{3,15}$/' }], res)
		if (await User.findOne({ phone_number })) return response.error(103, "already in use", [{ "key": 'phone_number', "value": phone_number }], res)
		if (confirmationIP && Date.now() - confirmationIP.datetime <= 60000 || confirmationPhoneNumber && Date.now() - confirmationPhoneNumber.datetime <= 60000) return response.error(6, "too frequent requests", [{ "key": 'left', "value": 60 - (confirmationIP && Date.now() - confirmationIP.datetime <= 60 ? confirmationIP.datetime : confirmationPhoneNumber.datetime) + Date.now() }], res)

		var code = Math.round(Math.random() * (9999 - 1000) + 1000)

		import('node-fetch').then(({ "default": fetch }) => {
			fetch(`https://sms.ru/sms/send?api_id=3AC1C1C8-385F-BDBC-5BD8-CBF0748A8CB3&to=${phone_number}&msg=${code} — код для регистрации в сервисе «specter».&json=1`)
				.then(async smsRes => {
					let JSONRes = await smsRes.json()

					if (!JSONRes.sms) return response.systemError(JSONRes, res)
					if (JSONRes.sms[phone_number].status_code == 202) return response.error(104, "the phone number is incorrect", [{ "key": 'phone_number', "value": phone_number }], res)
					if (JSONRes.sms[phone_number].status_code != 100) return response.systemError(JSONRes.sms[phone_number], res)

					await Confirmation.findOneAndDelete({ "ip": ip })
					await Confirmation.findOneAndDelete({ "phone_number": phone_number })

					let confirmation = new Confirmation({ "ip": ip, "phone_number": phone_number, "code": code, "datetime": Date.now() })
					await confirmation.save()

					let confirm_token = jwt.sign({
						"type": 'confirm_signup',
						"service": service,
						"confirm_id": confirmation._id
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

		var confirmation = await Confirmation.findOne({ "_id": req.token_payload.confirm_id })

		if (req.token_payload.type != 'confirm_signup' || !confirmation) {
			let error_details = []
			if (req.token_payload.type != 'confirm_signup') error_details.push({ "key": 'type', "value": req.token_payload.type, "required": 'confirm_signup' })
			if (!confirmation) error_details.push({ "key": 'id', "value": req.token_payload.id })
			return response.error(3, "invalid access token", error_details, res)
		}
		if (!code) return response.error(4, "one of the required parameters was not passed", [{ "key": 'code', "value": 'required' }], res)
		if (confirmation.code != code) return response.error(105, "invalid confirmation code", [{ "key": 'code', "value": code }], res)

		let signup_token = jwt.sign({
			"type": 'signup',
			"service": req.token_payload.service,
			"phone_number": confirmation.phone_number
		}, config.JWT, { "expiresIn": '30m' })

		return response.send({ "signup_token": `Bearer ${signup_token}` }, res)
	} catch (error) {
		return response.systemError(error, res)
	}

}

exports.signup = async (req, res) => {

	try {
		var password = req.query.password
		var phone_number = req.token_payload.phone_number

		if (req.token_payload.type != 'signup') return response.error(3, "invalid access token", [{ "key": 'type', "value": req.token_payload.type, "required": 'signup' }], res)
		if (!password) return response.error(4, "one of the required parameters was not passed", [{ "key": 'password', "value": 'required' }], res)
		if (!password.match(/^[a-zа-я0-9_.%+@$#!-]{8,128}$/i)) return response.error(5, "invalid parameter value", [{ "key": 'password', "value": password, "regexp": '/^[a-zа-я0-9_.%+@$#!-]{8,128}$/i' }], res)
		if (await User.findOne({ phone_number })) return response.error(103, "already in use", [{ "key": 'phone_number', "value": phone_number }], res)

		var user = new User({ "phone_number": phone_number, "password": passwordHash.generate(password) })
		await user.save()

		let service_auth_token = jwt.sign({
			"type": 'service_auth',
			"service": req.token_payload.service,
			"ecost_id": user._id
		}, config.JWT, { "expiresIn": '30m' })

		return response.send({ "service_auth_token": `Bearer ${service_auth_token}` }, res)
	} catch (error) {
		return response.systemError(error, res)
	}

}