# -*- coding: UTF-8 -*-
# @author =__Uluç Furkan Vardar__
# date = 2019-07-18
# version = 3.0

import botocore.exceptions
import boto3
import json
import uuid


class Cognito_controller():
	def __init__(self, USER_POOL_ID, CLIENT_ID):
		self.client = boto3.client('cognito-idp','eu-west-1')
		self.USER_POOL_ID = USER_POOL_ID
		self.CLIENT_ID = CLIENT_ID
	def UNKNOWN_ERROR(self,e):
		return None, 'Unknown error, '+str(e)
	def confirm_password(self, email, confirmation_code, new_password):
		try:
			resp = self.client.confirm_forgot_password( ClientId         = self.CLIENT_ID     ,
		                                                Username         = email             ,
		                                                ConfirmationCode = confirmation_code ,
		                                                Password         = new_password       )
		except self.client.exceptions.UserNotFoundException as e:
			return None, 503
		except self.client.exceptions.ExpiredCodeException as e:
			return None, 504
		except self.client.exceptions.CodeMismatchException as e:
			return None, 505
		except Exception as e :
			return self.UNKNOWN_ERROR(e)
		return resp, None


	def reset_password(self, email):
		try:
			resp = self.client.admin_reset_user_password(   UserPoolId = self.USER_POOL_ID,
															Username   = email              )
		except self.client.exceptions.NotAuthorizedException as e:
			return None, 501
		except self.client.exceptions.LimitExceededException as e:
			return None, 502			
		except Exception as e :
			print (e)
			return self.UNKNOWN_ERROR(e)
		return resp, None


	def log_in(self, email, password , AuthFlow_ = 'ADMIN_NO_SRP_AUTH' ):
		try:
		    resp = self.client.admin_initiate_auth( UserPoolId = self.USER_POOL_ID,
												    ClientId   = self.CLIENT_ID,
												    AuthFlow   = AuthFlow_ ,
												    AuthParameters ={
																        'USERNAME': email,
																        'PASSWORD': password
															        },
												    ClientMetadata ={
																        'username': email,
																        'password': password
												        })
		except self.client.exceptions.NotAuthorizedException as e:
		    return None, 401
		except self.client.exceptions.PasswordResetRequiredException as e:
		    return None, 402
		except self.client.exceptions.UserNotFoundException as e:
			return None, 403
		except self.client.exceptions.InvalidParameterException as e:
			return None,406
		except Exception as e:
		    print(e)
		    return self.UNKNOWN_ERROR(e)
		return resp, None		

	def delete_user(self, user_email):
		try:
			resp = self.client.admin_delete_user(
		    	        UserPoolId= self.USER_POOL_ID ,
		        	    Username = user_email
					)
			return True, None
		except self.client.exceptions.UserNotFoundException as e:
			return None, 7077
		except Exception as e:
		    print(e)
		    return self.UNKNOWN_ERROR(e)
		return response, None



	def change_password(self, email, old_password, new_password):
		resp, msg = self.log_in(email, old_password)
		
		if msg != None:
			return None, msg
		if resp.get('ChallengeName','') == 'NEW_PASSWORD_REQUIRED':
			Session = resp['Session']
			resp,msg = self.force_change_password(Session, email, new_password, 'NEW_PASSWORD_REQUIRED')
			return resp,msg
		else:
		    try:
		        response = self.client.change_password(
		            PreviousPassword = old_password,
		            ProposedPassword = new_password,
		            AccessToken = resp['AuthenticationResult']['AccessToken']
		        )             
		    except Exception as e:
		        print(e)
		        return self.UNKNOWN_ERROR(e)
		    return response, None


	def get_user_info(self, AccessToken_):
		try:
			resp = self.client.get_user(AccessToken = AccessToken_)
		except self.client.exceptions.NotAuthorizedException as e:
			return None, 301
		except self.client.exceptions.InvalidParameterException as e:
			return None,406			
		except Exception as e:
			return self.UNKNOWN_ERROR(e)
		return resp, None

	def get_user_type(self, AccessToken):
		resp, msg = self.get_user_info(AccessToken)
		if msg != None:
			return resp, msg
		for attribute in resp['UserAttributes']:
			if attribute['Name'] == 'custom:user_type':
				return attribute['Value'], None

	def is_admin(self, AccessToken):
		resp, msg = self.get_user_info(AccessToken)
		if msg != None:
			return resp, msg, None
		
		flag = False
		admin_user_name = ''
		for attribute in resp['UserAttributes']:
			if attribute['Name'] == 'custom:user_type':
				if attribute['Value'] == 'admin':
					flag = True
			elif attribute['Name'] == 'name':
				admin_user_name = attribute['Value']
		if flag == False:
			return None, 302, None	
		return True, None, admin_user_name
	def is_instructor_or_admin(self, AccessToken):
		resp, msg = self.get_user_info(AccessToken)
		if msg != None:
			return resp, msg, None
		
		flag = False
		admin_user_name = ''
		for attribute in resp['UserAttributes']:
			if attribute['Name'] == 'custom:user_type':
				if attribute['Value'] == 'admin' or attribute['Value'] == 'instructor':
					flag = True
			elif attribute['Name'] == 'name':
				admin_user_name = attribute['Value']
		if flag == False:
			return None, 302 , None	
		return True, None, admin_user_name	
	def create_user(self, username, email, user_type, institution = 'Test_Grubu', tempPassword = (str( uuid.uuid4() ).replace("-",""))[:10],  ):
		# first we must verfy the Creator is a admin
		'''
		resp, mgs = self.is_admin(admin_user_name, admin_user_password)
		if msg != None:
			return resp, msg		
		'''
		# -------
		try:
		    response = self.client.admin_create_user(
		            UserPoolId= self.USER_POOL_ID ,
		            Username = email,
		            UserAttributes=[
		                {
		                    'Name': 'name',
		                    'Value': username
		                },
		                {
		                    'Name': 'custom:user_type',
		                    'Value': user_type
		                },
		                {	'Name' : 'custom:institution',
		                	'Value': institution 
		                },
		                {
		                    "Name": "email",
		                    "Value": email
		                },                    
		                {
		                    "Name": "email_verified",
		                    "Value": "true"
		                }                    
		            ],
		            TemporaryPassword = tempPassword,
		            ForceAliasCreation = True,
		            DesiredDeliveryMediums=['EMAIL']
		        )       
		except self.client.exceptions.UsernameExistsException as e: 

		    return None, 404
		except Exception as e:
		    print(e)
		    return self.UNKNOWN_ERROR(e)
		return response, None

	def force_change_password(self, Session, email, new_password, ChallengeName):
		try:
		    resp = self.client.admin_respond_to_auth_challenge(
		            UserPoolId = self.USER_POOL_ID,
		            ClientId   = self.CLIENT_ID ,
		            ChallengeName = ChallengeName,
		            Session = Session,
		            ChallengeResponses={
		                    'NEW_PASSWORD' : new_password,
		                    'DESIRED PASSWORD' : new_password,
		                    'USERNAME' : email
		            })
		except Exception as e:
		    print(e)
		    return self.UNKNOWN_ERROR(e)
		return resp, None
	

    
	def reset_password(self, email):
		try:
		    resp = self.client.admin_reset_user_password(   UserPoolId = self.USER_POOL_ID,
		                                                    Username   = email              )
		except self.client.exceptions.NotAuthorizedException as e:
			return None, 501
		except self.client.exceptions.LimitExceededException as e:
			return None, 502			
		except Exception as e :
		    print (e)
		    return self.UNKNOWN_ERROR(e)
		return resp, None
	
