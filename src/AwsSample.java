/*
 * Copyright 2010 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License").
 * You may not use this file except in compliance with the License.
 * A copy of the License is located at
 *
 *  http://aws.amazon.com/apache2.0
 *
 * or in the "license" file accompanying this file. This file is distributed
 * on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 * express or implied. See the License for the specific language governing
 * permissions and limitations under the License.
 * 
 * Modified by Sambit Sahu
 * Modified by Ketan Barve (kab719@nyu.edu)
 * 
 */
import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;

import com.amazonaws.AmazonServiceException;
import com.amazonaws.auth.AWSCredentials;
import com.amazonaws.auth.PropertiesCredentials;
import com.amazonaws.services.ec2.AmazonEC2;
import com.amazonaws.services.ec2.AmazonEC2Client;
import com.amazonaws.services.ec2.model.CreateSecurityGroupResult;
import com.amazonaws.services.ec2.model.CreateTagsRequest;
import com.amazonaws.services.ec2.model.DescribeAvailabilityZonesResult;
import com.amazonaws.services.ec2.model.DescribeImagesResult;
import com.amazonaws.services.ec2.model.DescribeInstanceStatusRequest;
import com.amazonaws.services.ec2.model.DescribeInstanceStatusResult;
import com.amazonaws.services.ec2.model.DescribeInstancesRequest;
import com.amazonaws.services.ec2.model.DescribeInstancesResult;
import com.amazonaws.services.ec2.model.DescribeKeyPairsResult;
import com.amazonaws.services.ec2.model.Image;
import com.amazonaws.services.ec2.model.Instance;
import com.amazonaws.services.ec2.model.InstanceStatus;
import com.amazonaws.services.ec2.model.KeyPairInfo;
import com.amazonaws.services.ec2.model.Reservation;
import com.amazonaws.services.ec2.model.RunInstancesRequest;
import com.amazonaws.services.ec2.model.RunInstancesResult;
import com.amazonaws.services.ec2.model.SecurityGroup;
import com.amazonaws.services.ec2.model.StartInstancesRequest;
import com.amazonaws.services.ec2.model.StopInstancesRequest;
import com.amazonaws.services.ec2.model.Tag;
import com.amazonaws.services.ec2.model.TerminateInstancesRequest;
import com.amazonaws.services.ec2.model.CreateSecurityGroupRequest;
import com.amazonaws.services.ec2.model.CreateKeyPairRequest;
import com.amazonaws.services.ec2.model.CreateKeyPairResult;
import com.amazonaws.services.ec2.model.KeyPair;
import com.amazonaws.services.ec2.model.IpPermission;
import com.amazonaws.services.ec2.model.AuthorizeSecurityGroupIngressRequest;
import com.amazonaws.services.elasticloadbalancing.model.InstanceState;

import ch.ethz.ssh2.Connection;
import ch.ethz.ssh2.Session;
import ch.ethz.ssh2.StreamGobbler;

public class AwsSample {

	/*
	 * Important: Be sure to fill in your AWS access credentials in the
	 *            AwsCredentials.properties file before you try to run this
	 *            sample.
	 * http://aws.amazon.com/security-credentials
	 */

	static AmazonEC2      ec2;

	public static void main(String[] args) throws Exception {

		String securityGroupName= "Secured_group";
		String privateKeyFileName= "Ketan.pem";
		String ipRanges = "0.0.0.0/0";
		String keypairValue= "Ketan_Key";

		
		
		AWSCredentials credentials = new PropertiesCredentials(
				AwsSample.class.getResourceAsStream("AwsCredentials.properties"));

		/*********************************************
		 * 
		 *  #1 Create Amazon Client object
		 *  
		 *********************************************/
		System.out.println("Step #1 we are creating an Amazon Client object");
		ec2 = new AmazonEC2Client(credentials);

		try {
			
			/*********************************************
			 * 
			 *  #2 Describe Availability Zones.
			 *  
			 *********************************************/
			System.out.println("#2 Describe Availability Zones.");
			DescribeAvailabilityZonesResult availabilityZonesResult = ec2.describeAvailabilityZones();
			System.out.println("You have access to " + availabilityZonesResult.getAvailabilityZones().size() + " Availability Zones.");

			


			/*********************************************
			 *                 
			 *  #3 Describe Key Pair
			 *                 
			 *********************************************/
			System.out.println("#comment Describing Key Pair in console");
			DescribeKeyPairsResult dkr = ec2.describeKeyPairs();
			System.out.println(dkr.toString());

			/*********************************************
			 * 
			 *  #4 Describe Current Instances
			 *  
			 *********************************************/
			System.out.println("#4 Describe Current Instances");
			DescribeInstancesResult describeInstancesRequest = ec2.describeInstances();
			List<Reservation> reservations = describeInstancesRequest.getReservations();
			Set<Instance> instances = new HashSet<Instance>();
			// add all instances to a Set.
			for (Reservation reservation : reservations) {
				instances.addAll(reservation.getInstances());
			}

			System.out.println("You have following" + instances.size() + " Amazon EC2 instance(s).");
			for (Instance ins : instances){

				// instance id
				String instanceId = ins.getInstanceId();

				// instance state
				com.amazonaws.services.ec2.model.InstanceState is = ins.getState();
				System.out.println(instanceId+" "+is.getName());
			}

			/*********************************************
			 * #5 Create a security Group
			 *********************************************/
			CreateSecurityGroupRequest createSecurityGroupRequest = new CreateSecurityGroupRequest();
			createSecurityGroupRequest.withGroupName("Secured_Group")
			.withDescription("Cloud_Secured");

			CreateSecurityGroupResult createSecurityGroupResult = ec2.createSecurityGroup(createSecurityGroupRequest);
			System.out.println("Group name:" + securityGroupName);

			/**************************************************
			 * Authorize security group for the TCP, SSH and HTTP for inbound with the IPRange
			 ***************************************************/
			
			IpPermission ipPermission= new IpPermission();
			ipPermission.withIpRanges(ipRanges).withIpProtocol("tcp").withFromPort(0).withToPort(65535);
			System.out.println("TCP Permissions set");

			
			IpPermission sshPermission= new IpPermission();
			sshPermission.withIpRanges(ipRanges).withIpProtocol("tcp").withFromPort(22).withToPort(22);
			System.out.println("SSH Permissions set");

			IpPermission httpPermission= new IpPermission();
			httpPermission.withIpRanges(ipRanges).withIpProtocol("tcp").withFromPort(80).withToPort(80);
			System.out.println("HTTP permissions set");

			AuthorizeSecurityGroupIngressRequest authorizeSecurityGroupIngressRequest= new AuthorizeSecurityGroupIngressRequest();
			authorizeSecurityGroupIngressRequest.withGroupName(securityGroupName).withIpPermissions(ipPermission).withIpPermissions(sshPermission).withIpPermissions(httpPermission);

			ec2.authorizeSecurityGroupIngress(authorizeSecurityGroupIngressRequest);
			System.out.println("Inbound traffic is allowed for SSh and TCP within the IP Range");
			
			/*********************************************
			 * Create a Key Pair
			 **********************************************/
			CreateKeyPairRequest createKeyPairRequest= new CreateKeyPairRequest();
			createKeyPairRequest.withKeyName(keypairValue);

			CreateKeyPairResult createKeyPairResult=ec2.createKeyPair(createKeyPairRequest);

			com.amazonaws.services.ec2.model.KeyPair keyPair= new com.amazonaws.services.ec2.model.KeyPair();
			keyPair= createKeyPairResult.getKeyPair();
			System.out.println("Key pair generated is "+ keyPair);

			
			/******************************************
			 * Now we are saving Private key to a .pem file
			 *******************************************/
			File privateKeyFile = new File(privateKeyFileName);
			try{
				BufferedWriter bufferedWriter = new BufferedWriter(new FileWriter(privateKeyFile));
				bufferedWriter.write(keyPair.getKeyMaterial());
				bufferedWriter.flush();
				bufferedWriter.close();
			}
			catch(IOException exception){
				exception.printStackTrace();
			}
			
			
			/*********************************************
			 * 
			 *  #6 Create an Instance
			 *  
			 *********************************************/
			System.out.println("#5 Now we are Createing an Instance");
			String imageId = "ami-76f0061f"; //Basic 32-bit Amazon Linux AMI
			int minInstanceCount = 1; // create 1 instance
			int maxInstanceCount = 1;
			RunInstancesRequest rir = new RunInstancesRequest();
			rir.withImageId(imageId).withInstanceType("t1.micro").withMinCount(minInstanceCount).withMaxCount(maxInstanceCount)
			.withKeyName(keypairValue).withSecurityGroups(securityGroupName);
			RunInstancesResult result = ec2.runInstances(rir);

			//get instanceId from the result
			List<Instance> resultInstance = result.getReservation().getInstances();
			String createdInstanceId = null;
			for (Instance ins : resultInstance){
				createdInstanceId = ins.getInstanceId();
				System.out.println("New instance has been created: "+ins.getInstanceId());
			}


			/*********************************************
			 * 
			 *  #7 Create a 'tag' for the new instance.
			 *  
			 *********************************************/
			System.out.println("#6 Createing for the new instance.");
			List<String> resources = new LinkedList<String>();
			List<Tag> tags = new LinkedList<Tag>();
			Tag nameTag = new Tag("Name", "MyFirstInstance");

			resources.add(createdInstanceId);
			tags.add(nameTag);

			CreateTagsRequest ctr = new CreateTagsRequest(resources, tags);
			ec2.createTags(ctr);

			/********************
			 * Get Instance Information
			 */

			DescribeInstanceStatusRequest describeInstanceStatusRequest=
					new DescribeInstanceStatusRequest().withInstanceIds(createdInstanceId);
			DescribeInstanceStatusResult describeInstanceStatusResult=
					ec2.describeInstanceStatus(describeInstanceStatusRequest);
			List<InstanceStatus> state = describeInstanceStatusResult.getInstanceStatuses();
			while(state.size()<1){
				System.out.println("Instance is being create. Please Wait");
				Thread.sleep(10000);
				describeInstanceStatusResult=
						ec2.describeInstanceStatus(describeInstanceStatusRequest);
				state = describeInstanceStatusResult.getInstanceStatuses();

			}

			// Getting information 
			DescribeInstancesRequest instancesRequest= new DescribeInstancesRequest().withInstanceIds(createdInstanceId);
			DescribeInstancesResult describeInstancesResult= ec2.describeInstances(instancesRequest);

			Instance instance = describeInstancesResult.getReservations().get(0)
					.getInstances().get(0);

			StringBuffer resultBuffer= new StringBuffer();
			resultBuffer.append("Private DNS name: " + instance.getPrivateDnsName()+ "\n");
			resultBuffer.append("Public DNS name: " + instance.getPublicDnsName()+ "\n");
			resultBuffer.append("Private IP Address: "+ instance.getPrivateIpAddress()+ "\n");
			resultBuffer.append("Public IP Address: "+ instance.getPublicIpAddress()+ "\n");
			System.out.println(resultBuffer.toString());
			/*********************************************
			 * 
			 *  #8 Stop/Start an Instance
			 *  
			 *********************************************/
			System.out.println("#7 Stop the Instance");
			List<String> instanceIds = new LinkedList<String>();
			instanceIds.add(createdInstanceId);

			//stop
			StopInstancesRequest stopIR = new StopInstancesRequest(instanceIds);
			// ec2.stopInstances(stopIR);

			//start
			StartInstancesRequest startIR = new StartInstancesRequest(instanceIds);
			//ec2.startInstances(startIR);


			/*********************************************
			 * 
			 *  #9 Terminate an Instance
			 *  
			 *********************************************/
			System.out.println("#8 Terminateing our Instance");
			TerminateInstancesRequest tir = new TerminateInstancesRequest(instanceIds);
			// ec2.terminateInstances(tir);


			/*********************************************
			 *  
			 *  #10 shutdown client object
			 *  
			 *********************************************/
			ec2.shutdown();



		} catch (AmazonServiceException ase) {
			System.out.println("Caught Exception: " + ase.getMessage());
			System.out.println("Reponse Status Code: " + ase.getStatusCode());
			System.out.println("Error Code: " + ase.getErrorCode());
			System.out.println("Request ID: " + ase.getRequestId());
		}


	}

}