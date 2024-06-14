//import (if needed)
const mongoose = require('mongoose')


//list of function
const connectToDB = () => {
    mongoose.connect(process.env.DB_URL).then(() => {
        console.log("Connected to Database");
    })
}

//export
module.exports = connectToDB;