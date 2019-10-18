db:
	sudo -u postgres dropdb --if-exists assertible_crypto_test
	sudo -u postgres createdb -Oassertible -Eutf8 assertible_crypto_test
