const models = require('../models');
const validator = require("fastest-validator");
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const signUp = async(req,res) => {
    const {firstname,lastname,email,password} = req.body;
  
    try{     
            const userAlreadyExist = await models.User.findOne({ where: { email } })
            if(userAlreadyExist) {
                res.status(409).json({
                    status:false,
                    message : "Email already exists!"
                })
                return; 
            }
            const user = {
                firstname,
                lastname,
                email,
                password
            }
            // creating a scheme for data validation
            const schema = {
                firstname : {type:"string",optional:false,max:100,trim:true,trimLeft:true,trimRight:true,empty:false,pattern:"^[a-zA-Z]+(?:\s+[a-zA-Z]+)*$"},
                lastname : {type:"string",optional:false,max:100,trim:true,trimLeft:true,trimRight:true,empty:false,pattern:"^[a-zA-Z]+(?:\s+[a-zA-Z]+)*$"},
                email : {type:"email", optional:false,empty:false,trim:true},
                password: {type:"string",optional:false,empty:false,min:7},
            }
            const v =  new validator();
            const validatorResponse = await v.validate(user,schema)
            if (validatorResponse !== true) {
                res.status(400).json({
                    message : "Validation failed",
                    error : validatorResponse
                })
                return;
            }
            const salt = await bcrypt.genSalt(10);
            const hashedPassword = await bcrypt.hash(password, salt);  
            const newuserObject = {firstname,lastname,email,password: hashedPassword}
            const newUser = await models.User.create(newuserObject); 
            if(newUser) res.status(201).json({status:true, message: "user created successfully!"}) 
    } 
    catch(error){
            res.status(500).json({
                status: false,
                message : "Oops..,an error occured, please try again later",
            })
    }
        
}


const login = async (req,res) => {
    const {email,password} = req.body;
    const user = {
        email,
        password
    }
    // creating a scheme for data validation
    const schema = {
        email : {type:"email", optional:false,empty:false,trimLeft:true,trimRight:true},
        password: {type:"string",optional:false,empty:false,min:7},
    }
    const v =  new validator();
    const validatorResponse = await v.validate(user,schema)
    if (validatorResponse !== true) {
        res.status(400).json({
            message : "Validation failed",
            error : validatorResponse
        })
        return;
    }
    else {
        try{
            const user = await models.User.findOne({where:{email}});
            if(user === null){
                res.status(400).json({
                    status: false,
                    message : "Invalid credentials! ",
                })
            }

            else{
                const passwordMatch = await bcrypt.compare(password,user.password);
                if(passwordMatch){
                const token = await jwt.sign({
                    email:user.email,
                    userId:user.id
                }, process.env.JWT_KEY);   
                    if(token) res.status(200).json({status:true,message:"User Login Successfully",id:user.id,token,firstname:user.firstname,lastname:user.lastname,email:user.email})
                    else{
                        res.status(400).json({
                            status: false,
                            message : "something went wrong while logging you in!",
                        })
                    }
                }
                else{
                    res.status(400).json({
                        status: false,
                        //used generic message to prevent hackers from knowing what's up.
                        message : "You have entered a wrong email or password",
                    })
                }
            }
        }
        catch(error){
            res.status(500).json({
                status: false,
                message : "Oops..,an error occured, please try again later",
            })
        }
}
    }
    

module.exports = {
    signUp,
    login
}


