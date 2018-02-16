var express = require("express");
var app = express();
var bodyParser = require("body-parser");
var mongoose = require("mongoose");
var SHA256 = require("crypto-js/sha256");
var encBase64 = require("crypto-js/enc-base64");
var uid2 = require("uid2");

app.use(bodyParser.json());

mongoose.connect("mongodb://localhost:27017/API-RBNB");

// création du model user
var userSchema = mongoose.Schema({
  account: {
    username: {
      type: String, //permet de définir un type string
      unique: true // permet d'avoir la donnée unique
    },
    biography: String
  },
  email: String,
  token: String,
  hash: String,
  salt: String
});

var users = mongoose.model("user", userSchema);

//service connection

app.post("/api/user/log_in", function(req, res) {
  var email = req.body.email;
  users.findOne(
    {
      email: email
    },
    function(err, user) {
      if (err) {
        console.log(err);
      } else {
        if (user) {
          var userPassword = SHA256(req.body.password + user.salt).toString(
            encBase64
          );
          if (user.hash === userPassword) {
            res.json({
              _id: user._id,
              token: user.token,
              account: {
                username: user.account.username,
                biography: user.account.biography
              }
            });
          } else {
            console.log("login information incorrect");
          }
        }
      }
    }
  );
});
// service inscription
app.post("/api/user/sign_up", function(req, res) {
  var salt = uid2(64);
  var hash = SHA256(req.body.password + salt).toString(encBase64);

  var user = new users();
  user.account.username = req.body.username;
  user.account.biography = req.body.biography;
  user.email = req.body.email;
  user.hash = hash;
  user.token = uid2(64);
  user.salt = salt;

  user.save(function(err, obj) {
    if (err) {
      res.json(err);
    } else {
      res.json({
        _id: obj._id,
        token: uid2(20),
        account: {
          username: obj.account.username,
          biography: obj.account.biography
        }
      });
    }
  });
});

//service consultation profil de l'utilisateur

app.get("/api/user/:id", function(req, res) {
  var auth = req.headers.authorization;
  if (!auth) {
    return res.json({
      error: {
        code: 48326,
        message: "Invalid token"
      }
    });
  }
  var token = auth.split(" ")[1];
  users.findOne(
    {
      token: token
    },
    function(err, user) {
      if (err) {
        res.send(err);
      } else {
        if (user) {
          res.json({
            _id: users._id,
            account: {
              username: user.account.username,
              biography: user.account.biography
            }
          });
        } else {
          res.json({
            error: {
              code: 9473248,
              message: "Invalid token"
            }
          });
        }
      }
    }
  );
});

app.listen(3000, function() {
  console.log("server has started");
});
