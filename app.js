const express = require('express');
const app = express();
app.set('view engine', 'ejs');
app.use(express.json());
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
app.use(cookieParser());
app.set('views',__dirname);

const config = require('./config');

const {OAuth2Client} = require('google-auth-library');

const port = config.port;


const client = new OAuth2Client(config.oauth2Credentials.client_id, config.oauth2Credentials.client_secret, config.oauth2Credentials.redirect_uris[0]);

// getting login url

app.get('/',(req,res)=>{

// function that will generate a url that we will our users to. we have to pass access scopes 
// that user has to agree to 

const loginLink = client.generateAuthUrl({
    access_type:'offline',//offline means that we want to keep on sending the user data without asking for consent
    scope:config.oauth2Credentials.scopes
})
  return res.render('index', {loginLink:loginLink})
});


app.get('/auth_callback', async (req,res)=>{

  if (req.query.error) {
    // The user did not give us permission.
    return res.redirect('/');
  } else {
    client.getToken(req.query.code, function(err, token) {
        if (err)
          return res.redirect('/');
  
        // Store the credentials given by google into a jsonwebtoken in a cookie called 'jwt'
        res.cookie('jwt', jwt.sign(token, config.JWTsecret));
        return res.redirect('/getUserData');
      });
    }
 
});

app.get('/getUserData',async(req,res)=>{
    let idToken = req.cookies.jwt;
    if(!idToken) return res.redirect('/');

    let google_data = jwt.decode(idToken,config.JWTsecret);  //decode jwt 
    
    idToken = google_data.id_token;
    let verifyToken = await client.verifyIdToken({idToken, audience:config.oauth2Credentials.client_id}); //decode google code

    console.log(verifyToken );


    res.render('data',{user:verifyToken.payload});
})


app.get('/test',(req,res)=>{
    console.log('hii');
    res.send('hi')
})

// getting the user from google with code


// getting the current user

app.listen(port,()=>{console.log('server running on '+port)});