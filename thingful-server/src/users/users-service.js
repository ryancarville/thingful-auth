const xss = require('xss');
const bcrypt = require('bcryptjs');
const REGEX_UPPER_LOWER_NUMBER_SPECIAL = /(?=.*[a-z])(?=.*[A-Z])(?=.*[0-9])(?=.*[!@#\$%\^&])[\S]+/;

const UserService = {
	hasUserWithUserName(db, user_name) {
		return db('thingful_users')
			.where({ user_name })
			.first()
			.then(user => !!user);
	},

	insertUser(db, newUser) {
		return db
			.insert(newUser)
			.into('thingful_users')
			.returning('*')
			.then(([user]) => user);
	},

	validatePassword(password) {
		if (password.length < 8) {
			return 'Password needs to be at least 8 characters long';
		}
		if (password.length > 72) {
			return 'Password needs to be less thant 72 characters long';
		}
		if (password.startsWith(' ') || password.endsWith(' ')) {
			return 'Password must not have a empty space at the starts or end';
		}
		if (!REGEX_UPPER_LOWER_NUMBER_SPECIAL.test(password)) {
			return 'Password must contain at least 1 upper case letter, 1 lower case letter, 1 number and 1 special charater';
		}
		return null;
	},

	hashPassword(password) {
		return bcrypt.hash(password, 12);
	},

	serializeUser(user) {
		return {
			id: user.id,
			full_name: xss(user.full_name),
			user_name: xss(user.user_name),
			nick_name: xss(user.nick_name),
			date_created: new Date(user.date_created)
		};
	}
};

module.exports = UserService;
