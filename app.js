// Here we used bcrypt hashing algorith which is more secure than md5 insted of md5
const express = require("express");
const ejs = require("ejs");
const bodyParser = require("body-parser");
const mongoose = require("mongoose");
// import bcrypt library
const bcrypt = require('bcrypt');
// Number of hashing rounds to perform
const saltRounds = 5;

const app = express();
const port = process.env.PORT || 3000;
app.use(bodyParser.urlencoded({extended: true}));
app.use(express.static("public"));
app.set('view engine', 'ejs');

mongoose.set('strictQuery', true);
mongoose.connect(process.env.MONGO_URL, {useNewUrlParser: true});

const userSchema = new mongoose.Schema({
  email: {
    type: String,
    required: true
  },
  password: {
    type: String,
    required: true
  }
});


const User = mongoose.model("User", userSchema);

app.get("/", function (req,res) {
  res.render("home");
});

app.get("/login", function (req,res) {
  res.render("login");
});

app.get("/register", function (req,res) {
  res.render("register");
});

app.post("/register", function (req,res) {

  // pass the password , number of saltrounds to bcrypt function , 3rd argument is call back which gives
  // err if any and encrypted hash.
  // Bcrypt hashing algorithm take password adds random salt to it to produce string like salt+password and hashes
  // it , then output is combined with hash an hashed again,this process is repeated number of salt round specified.
  bcrypt.hash(req.body.password, saltRounds, function(err, hash) {
    if(err){
      console.log(err);
    } else {
      const newUser = new User({
        email: req.body.username,
        password: hash
      });
      newUser.save(function (err) {
        if(err){
          console.log(err);
        } else {
          res.render("secrets");
        }
      });
    }
  });
});

app.post("/login", function (req,res) {
  const username = req.body.username;
  const password = req.body.password;

  User.findOne({email: username}, function (err, foundOne) {
    if(err){
      console.log(err);
    } else {
      // To validate we use compare function of bcrypt library , we pass password
      // from user and hash from database and their is callback function where result
      // is bool if matched true else false.
      bcrypt.compare(password, foundOne.password, function(err, result) {
        if(result == true){
          res.render("secrets");
        }else{
          res.redirect("/");
        }
      });
    }
  });
});

app.listen(port, function () {
  console.log("Server started on port 3000");
});
