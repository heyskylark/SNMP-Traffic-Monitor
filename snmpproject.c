/*
 * snmpproject.c
 *
 *  Created on: Nov 1, 2016
 *      Author: Brandon Feist
 */

#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>
#include <math.h>
#include <unistd.h>

/**
 * Initiates and SNMP Get on the specified session and returns the variable_list results.
 * @param sessionHande: The SNMP session to do the Get on.
 * @param oid: The OID to initiate Get on.
 * @param oidLen: The OID length
 */
struct variable_list *snmpGet(struct snmp_session *sessionHandle, oid *oid, size_t oidLen) {
	struct snmp_pdu *pdu;
	struct snmp_pdu *pduResponse;

	// Create PDU for SNMP Get.
	pdu = snmp_pdu_create(SNMP_MSG_GET);
	// Add NULL to set value of PDU for outgoing request.
	snmp_add_null_var(pdu, oid, oidLen);

	// Check status and return.
	int status = snmp_synch_response(sessionHandle, pdu, &pduResponse);
	netsnmp_ds_set_boolean(NETSNMP_DS_LIBRARY_ID, NETSNMP_DS_LIB_QUICK_PRINT, 1);
	if (status == STAT_SUCCESS && pduResponse->errstat == SNMP_ERR_NOERROR) {
		return pduResponse->variables;
	}

	// Free snmp_pdu structure pointed to by pduResponse
	if (pduResponse) {
		snmp_free_pdu(pduResponse);
	}
	return 0;
}

/**
 * Initiates and SNMP GetNext on the specified session and returns the variable_list results.
 * @param sessionHande: The SNMP session to do the GetNext on.
 * @param oid: The OID to initiate GetNext on.
 * @param oidLen: The OID length
 */
struct variable_list *snmpGetNext(struct snmp_session *sessionHandle, oid *oid, size_t oidLen) {
	struct snmp_pdu *pdu;
	struct snmp_pdu *pduResponse;

	// Create PDU for SNMP GetNext.
	pdu = snmp_pdu_create(SNMP_MSG_GETNEXT);
	// Add NULL to set value of PDU for outgoing request.
	snmp_add_null_var(pdu, oid, oidLen);

	// Check status and return.
	int status = snmp_synch_response(sessionHandle, pdu, &pduResponse);
	netsnmp_ds_set_boolean(NETSNMP_DS_LIBRARY_ID, NETSNMP_DS_LIB_QUICK_PRINT, 1);
	if (status == STAT_SUCCESS && pduResponse->errstat == SNMP_ERR_NOERROR) {
		return pduResponse->variables;
	}

	// Free snmp_pdu structure pointed to by pduResponse
	if (pduResponse) {
		snmp_free_pdu(pduResponse);
	}
	return 0;
}


/**
 * Initiates and SNMP walk of a specified oid root and writes the results to the given FILE.
 * @param sessionHande: The SNMP session to do the walk on.
 * @param oidRoot: The (OID root / MIB subtree) to walk on.
 * @param oidLen: The OID length
 * @param file: The file to write SNMPWalk results to
 */
int snmpWalk(struct snmp_session *sessionHandle, oid *oidRoot, size_t oidLen, FILE *file){
	struct snmp_pdu *pdu;
	struct snmp_pdu *pduResponse;
	struct variable_list *variables;

	oid nextOid[MAX_OID_LEN];
	size_t nextOidLength;

	int status;
	int isWalking = 1;
	int returnValue = 0; // returns -1 if error

	// Copy oid and oidLen parameters to new local variables.
	memmove(nextOid, oidRoot, oidLen * sizeof(oid));
	nextOidLength = oidLen;

	while(isWalking) {
		// Create PDU for SNMPGetNext
		pdu = snmp_pdu_create(SNMP_MSG_GETNEXT);
		// Add NULL to set value of PDU for outgoing request.
		snmp_add_null_var(pdu, nextOid, nextOidLength);

		status = snmp_synch_response(sessionHandle, pdu, &pduResponse);
		netsnmp_ds_set_boolean(NETSNMP_DS_LIBRARY_ID, NETSNMP_DS_LIB_QUICK_PRINT, 1);

		if (status == STAT_SUCCESS) {
			if (pduResponse->errstat == SNMP_ERR_NOERROR) {
				// Check the returned variables.
				for (variables = pduResponse->variables; variables; variables = variables->next_variable) {
					// Check if we are still within the subtree of the MIB.
					if ((variables->name_length < oidLen) || (memcmp(oidRoot, variables->name, oidLen * sizeof(oid)) != 0))  {
						isWalking = 0;
						continue;
					}

					// Write returned data to the walkResult.txt file.
					fprint_value(file,variables->name, variables->name_length, variables);

					// Check if not at end of MIB view and is an object and instance.
					if ((variables->type != SNMP_ENDOFMIBVIEW) &&
							(variables->type != SNMP_NOSUCHOBJECT) &&
							(variables->type != SNMP_NOSUCHINSTANCE)) {

						if (snmp_oid_compare(nextOid, nextOidLength, variables->name, variables->name_length) >= 0) {
							fprintf(stderr, "Error: OID not increasing: ");
							fprint_objid(stderr, nextOid, nextOidLength);
							fprintf(stderr, " >= ");
							fprint_objid(stderr, variables->name, variables->name_length);
							fprintf(stderr, "\n");
							isWalking = 0;
							returnValue = -1;
						}

						memmove((char *) nextOid, (char *) variables->name, variables->name_length * sizeof(oid));
						nextOidLength = variables->name_length;

					} else {
						isWalking = 0;
					}
				}
			} else {
				// Stop walking and print the error that is returned.
				isWalking = 0;

				if (pduResponse->errstat == SNMP_ERR_NOSUCHNAME) {
					printf("End of MIB\n");
				} else {
					fprintf(stderr, "Error in packet.\nReason: %s\n",
							snmp_errstring(pduResponse->errstat));
					if (pduResponse->errindex != 0) {
						fprintf(stderr, "Failed object: ");
						int count;
						for (count = 1, variables = pduResponse->variables;
								variables && count != pduResponse->errindex;
								variables = variables->next_variable, count++);
						if (variables)
							fprint_objid(stderr, variables->name,
									variables->name_length);
						fprintf(stderr, "\n");
					}
					returnValue = -1;
				}
			}
		} else if(status == STAT_TIMEOUT) {
			netsnmp_session session;

			fprintf(stderr, "Timeout: No Response from %s\n",
					session.peername);
			isWalking = 0;
			returnValue = -1;
		} else {
			snmp_sess_perror("snmpwalk", sessionHandle);
			isWalking = 0;
			returnValue = -1;
		}

		if (pduResponse) {
			snmp_free_pdu(pduResponse);
		}
	}

	fclose(file);
	return returnValue;
}

/**
 * Establishes a SNMP session using the provided version, community, and hostname.
 * @param version: SNMP version
 * @param community: SNMP community string
 * @param hostName: SNMP agent IP address
 */
struct snmp_session *createSNMPSession(int version, char* community, char* hostName) {
	struct snmp_session session;
	struct snmp_session *sessionHandle;

	init_snmp("snmpproject");
	snmp_sess_init(&session);
	session.version = version;
	session.community = community;
	session.community_len = strlen(session.community);
	session.peername = hostName;
	sessionHandle = snmp_open(&session);

	// Throw error if session failed to open.
	if (!sessionHandle) {
		snmp_perror("ack");
		snmp_log(LOG_ERR, "The session was not able to open.\n");
		exit(2);
	}

	return sessionHandle;
}

/**
 * Returns a long of the traffic data in inOct and outOct variable_list
 * @param variables: struct variable_list containing traffic data.
 */
long getTrafficData(struct variable_list *variables) {
	long *memRef;
	long trafficData;

	memRef = malloc(1 + variables->val_len);
	memcpy(memRef, variables->val.integer, variables->val_len);

	trafficData = *memRef;
	free(memRef);

	return trafficData;
}

/**
 * Takes two octet values and time interval and returns the KBs
 * @param startVal: Octet value at beggining of the interval.
 * @param endVal: Octet value at the end of the interval.
 * @param timeInterval: Time interval between Octet sampling.
 */
long trafficDeltaToKb(long startVal, long endVal, long timeInterval) {
	long returnVal = 0;

	if (endVal > startVal) {
		returnVal = ((endVal - startVal) * 8 / 1024) / timeInterval;
	} else {
		returnVal = (((endVal - startVal) * 8 * pow(2,32) / 1024)) / timeInterval;
	}

	return returnVal;
}

int main (int argc, char * argv[]) {
	char line1[256], line2[256];	// Stores FILE Input lines.

	if(argc < 5 || argc > 5) {
		printf("The correct number of parameters were not supplied: ");
		printf("(time interval | number of samples | community | hostname)\n");

		exit(1);
	}

	// Retrieve parameter data.
	char *endptr;
	int timeInterval = strtol(argv[1], &endptr, 10);
	int numOfSamples = strtol(argv[2], &endptr, 10);


	// check that both
	if(!(timeInterval > 0 && numOfSamples > 0)) {
		printf("Please ensure that both time interval and number of samples are positive values.\n");
		exit(1);
	}

	// Establish an SNMP session.
	struct snmp_session *sessionHandle = createSNMPSession(SNMP_VERSION_1,argv[3],argv[4]);

	// Retrieve ipAdEntIfIndex and ifAdEntAddr and then print.
	oid ifIP[MAX_OID_LEN];
	size_t ifIPLen = MAX_OID_LEN;
	oid ifOID[MAX_OID_LEN];
	size_t ifOIDLen = MAX_OID_LEN;

	read_objid("1.3.6.1.2.1.4.20.1.1", ifIP, &ifIPLen);
	read_objid("1.3.6.1.2.1.4.20.1.2", ifOID, &ifOIDLen);

	snmpWalk(sessionHandle, ifIP, ifIPLen, fopen("EntAddr.txt","w"));
	snmpWalk(sessionHandle, ifOID, ifOIDLen, fopen("EntIfIndex.txt","w"));

	FILE *entAddr;
	if((entAddr = fopen("EntAddr.txt", "r")) == NULL) {
		fprintf( stderr, "Error opening file EntAddr.txt\n" );
		exit( 1 );
	}
	FILE *entIfIndex;
	if((entIfIndex = fopen("EntIfIndex.txt", "r")) == NULL) {
		fprintf( stderr, "Error opening file EntIfIndex.txt\n" );
		exit( 1 );
	}

	printf("INTERFACES:\n");
	printf("______________________________\n");
	printf("| Interface |        IP       |\n");
	printf("______________________________\n");
	while(fgets(line1, sizeof(line1), entIfIndex)) {
		fgets(line2, sizeof(line2), entAddr);
		strtok(line1, "\n"); strtok(line2, "\n");

		printf("| %9s | %15s |\n", line1, line2);
	}
	printf("______________________________\n");

	fclose(entAddr);
	fclose(entIfIndex);

	// Retrieve the neighbors
	oid neighborIfIndex[MAX_OID_LEN];
	size_t neighborIfIndexLen = MAX_OID_LEN;
	oid neighborNetAddr[MAX_OID_LEN];
	size_t neighborNetAddrLen = MAX_OID_LEN;

	read_objid("1.3.6.1.2.1.4.22.1.1", neighborIfIndex, &neighborIfIndexLen);
	read_objid("1.3.6.1.2.1.4.22.1.3", neighborNetAddr, &neighborNetAddrLen);

	snmpWalk(sessionHandle, neighborIfIndex, neighborIfIndexLen, fopen("neighborsIfIndex.txt","w"));
	snmpWalk(sessionHandle, neighborNetAddr, neighborNetAddrLen, fopen("neighborsNetAddr.txt","w"));

	FILE *neighborIfFile, *neighborAddrFile;
	if((neighborIfFile = fopen("neighborsIfIndex.txt", "r")) == NULL) {
		fprintf( stderr, "Error opening file neighbors.txt\n" );
		exit( 1 );
	}
	if((neighborAddrFile = fopen("neighborsNetAddr.txt", "r")) == NULL) {
		fprintf( stderr, "Error opening file neighbors.txt\n" );
		exit( 1 );
	}

	printf("\nNEIGHBORS:\n");
	printf("______________________________\n");
	while(fgets(line1, sizeof(line1), neighborIfFile)) {
		fgets(line2, sizeof(line2), neighborAddrFile);
		strtok(line1, "\n"); strtok(line2, "\n");

		printf("| %9s | %15s |\n", line1, line2);
	}
	printf("______________________________\n");

	fclose(neighborIfFile);
	fclose(neighborAddrFile);

	// Calculate in and out traffic of interfaces.
	oid in[MAX_OID_LEN];
	size_t inLen = MAX_OID_LEN;
	oid out[MAX_OID_LEN];
	size_t outLen = MAX_OID_LEN;

	struct variable_list *inVar1, *inVar2;
	struct variable_list *outVar1, *outVar2;

	int seconds = 0;

	printf("\nTRAFFIC:\n");
	printf("___________________________________________________________\n");
	if((entIfIndex = fopen("EntIfIndex.txt", "r")) == NULL) {
		fprintf( stderr, "Error opening file EntIfIndex.txt\n" );
		exit( 1 );
	}
	while(fgets(line1, sizeof(line1), entIfIndex)) {
		strtok(line1, "\n");
		seconds = timeInterval;
		long ifIndex = atoi(line1);

		printf("\nInterface: %ld\n", ifIndex);
		printf("___________________________________________________________\n");
		printf("%-7s | %-17s | %-7s | %-17s\n", "Seconds", "IN Traffic (Kb/s)","Seconds", "OUT Traffic (Kb/s)") ;

		int currentSample;
		for (currentSample=0; currentSample< numOfSamples; currentSample++) {
			// Append current interface ifIndex to inOctet OID
			char inOctetOid[25] ="1.3.6.1.2.1.2.2.1.10.";
			char outOctetOid[25] ="1.3.6.1.2.1.2.2.1.16.";
			//strcat(inOctetOid, ifIndex);
			strcat(inOctetOid, line1);
			strcat(outOctetOid, line1);
			//google snmp inoctet
			read_objid(inOctetOid, in, &inLen);
			read_objid(outOctetOid, out, &outLen);

			inVar1 = snmpGet(sessionHandle, in, inLen);
			outVar1 = snmpGet(sessionHandle, out, outLen);
			sleep(timeInterval);
			inVar2 = snmpGet(sessionHandle, in, inLen);
			outVar2 = snmpGet(sessionHandle, out, outLen);

			printf("%-7d | %-17ld | %-7d | %-17ld\n", seconds,
					trafficDeltaToKb(getTrafficData(inVar1), getTrafficData(inVar2), timeInterval),
					seconds,
					trafficDeltaToKb(getTrafficData(outVar1), getTrafficData(outVar2), timeInterval));

			seconds += timeInterval;
		}

		printf("__________________________________________________________\n");
	}

	// CLOSE SNMP SESSION AND DELETE FILES CREATED.
	snmp_close(sessionHandle);
	SOCK_CLEANUP;

	remove("EntAddr.txt");
	remove("EntIfIndex.txt");
	remove("neighborsIfIndex.txt");
	remove("neighborsNetAddr.txt");

	return 0;
}
