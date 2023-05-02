'use strict'

const response = require('./../response')
const jwt = require('jsonwebtoken')
const config = require('./../config')
const passwordHash = require('password-hash')
const User = require('./../models/User')
const Confirmation = require('./../models/Confirmation')

exports.confirmPhoneNumber = async (req, res) => {

	try {
		var phone_number = req.query.phone_number
		if (phone_number[0] === '8') phone_number = phone_number.replace('8', '7')
		var ip = req.socket.remoteAddress

		var user = await User.findOne({ phone_number })
		let confirmationIP = await Confirmation.findOne({ "ip": ip })
		let confirmationPhoneNumber = await Confirmation.findOne({ "phone_number": phone_number })

		if (!phone_number) return response.error(4, "one of the required parameters was not passed", [{ "key": 'phone_number', "value": 'required' }], res)
		if (!user) return response.error(100, "the user is not registered", [{ "key": 'phone_number', "value": phone_number }], res)
		if (confirmationIP && Date.now() - confirmationIP.datetime <= 60000 || confirmationPhoneNumber && Date.now() - confirmationPhoneNumber.datetime <= 60000) return response.error(6, "too frequent requests", [{ "key": 'left', "value": 60 - (confirmationIP && Date.now() - confirmationIP.datetime <= 60 ? confirmationIP.datetime : confirmationPhoneNumber.datetime) + Date.now() }], res)

		var code = Math.round(Math.random() * (9999 - 1000) + 1000)

		import('node-fetch').then(({ "default": fetch }) => {
			fetch(`https://sms.ru/sms/send?api_id=3AC1C1C8-385F-BDBC-5BD8-CBF0748A8CB3&to=${phone_number}&msg=${code} — код для сброса пароля в аккаунте «ecost».&json=1`)
				.then(async smsRes => {
					let JSONRes = await smsRes.json()

					if (!JSONRes.sms || JSONRes.sms[phone_number].status_code != 100) return response.systemError(JSONRes, res)

					await Confirmation.findOneAndDelete({ "ip": ip })
					await Confirmation.findOneAndDelete({ "phone_number": phone_number })

					let confirmation = new Confirmation({ "ip": ip, "phone_number": phone_number, "code": code, "datetime": Date.now() })
					await confirmation.save()

					let confirm_token = jwt.sign({
						"type": 'confirm_password_reset',
						"service": 'ecost',
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

		var confirmation = await Confirmation.findOne({ "_id": req.token_payload.confirm_id })

		if (req.token_payload.type != 'confirm_password_reset' || !confirmation) {
			let error_details = []
			if (req.token_payload.type != 'confirm_password_reset') error_details.push({ "key": 'type', "value": req.token_payload.type, "required": 'confirm_password_reset' })
			if (!confirmation) error_details.push({ "key": 'id', "value": req.token_payload.id })
			return response.error(3, "invalid access token", error_details, res)
		}
		if (!code) return response.error(4, "one of the required parameters was not passed", [{ "key": 'code', "value": 'required' }], res)
		if (confirmation.code != code) return response.error(105, "invalid confirmation code", [{ "key": 'code', "value": code }], res)

		let password_reset_token = jwt.sign({
			"type": 'password_reset',
			"service": 'ecost',
			"ecost_id": req.token_payload.ecost_id
		}, config.JWT, { "expiresIn": '30m' })

		return response.send({ "password_reset_token": `Bearer ${password_reset_token}` }, res)
	} catch (error) {
		return response.systemError(error, res)
	}

}

exports.passwordReset = async (req, res) => {

	try {
		var password = req.query.password

		if (req.token_payload.type != 'password_reset') return response.error(3, "invalid access token", [{ "key": 'type', "value": req.token_payload.type, "required": 'confirm_password_reset' }], res)
		if (!password) return response.error(4, "one of the required parameters was not passed", [{ "key": 'password', "value": 'required' }], res)

		await EcostUser.updateOne({ "_id": req.token_payload.ecost_id }, { "$set": { "password": passwordHash.generate(password) } })

		return response.send(1, res)
	} catch (error) {
		return response.systemError(error, res)
	}

}