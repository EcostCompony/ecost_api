const app = require('express')()

const PORT = process.env.PORT || 3500

require('./middleware/passport')(require('passport'))
require('./settings/routes')(app)

const start = async () => {

	try {
		await require('mongoose').connect(require('./config').MONGODB_URI)
		app.listen(PORT, () => console.log(`App listen on port ${PORT}`))
	} catch (error) {
		console.log(error)
	}

}
start()