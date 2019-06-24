const bcrypt = require('bcyrptjs');

function requireAuth(req, res, next) {
	const authToken = req.get('Authorization') || '';

	let bearerToken;

	if (!authToken.toLowerCase().startsWith('bearer ')) {
		return res.status(401).json({ error: 'Missing bearer token' });
	} else {
		bearerToken = authToken.slice('bearer '.length, authToken.length);
	}

	const [tokenUserName, tokenPassword] = Buffer.from(bearerToken, 'base64')
		.toString()
		.split(':');

	if (!tokenUserName || !tokenPassword) {
		return res.status(401).json({ error: 'Unauthroized request' });
	}
	req.app
		.get('db')('thingful_users')
		.where({ user_name: tokenUserName })
		.first()
		.then(user => {
			if (!user) {
				return res.status(401).json({ error: 'Unauthorized request' });
			}
			return bcrypt
				.compare(tokenPassword, user.password)
				.then(passwordsMatch => {
					if (!passwordsMatch) {
						return res.status(401).json({ error: 'Unauthorized request' });
					}
					req.user = user;
					next();
				});
		})
		.catch(next);
}

module.exports = { requireAuth };
