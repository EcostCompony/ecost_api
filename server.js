const passport = require('passport')
const config = require('./config')

const app = require('express')()
const PORT = process.env.PORT || 3500

app.use(passport.initialize())

require('./middleware/passport')(passport)
require('./settings/routes')(app)

const start = async () => {

	try {
		await require('mongoose').connect(config.MONGODB)
		app.listen(PORT, () => console.log(`App listen on port ${PORT}`))
	} catch (error) {
		console.log(error)
	}

}
start()