CREATE TABLE `analystSettings` (
	`userId` int NOT NULL,
	`enabledModulesJson` text,
	`dorkIntensity` enum('focused','balanced','deep') NOT NULL DEFAULT 'balanced',
	`preferredModel` varchar(128),
	`updatedAt` timestamp NOT NULL DEFAULT (now()) ON UPDATE CURRENT_TIMESTAMP,
	CONSTRAINT `analystSettings_userId` PRIMARY KEY(`userId`)
);
--> statement-breakpoint
CREATE TABLE `entityRelationships` (
	`id` varchar(32) NOT NULL,
	`runId` varchar(32) NOT NULL,
	`sourceEntityId` varchar(32) NOT NULL,
	`targetEntityId` varchar(32) NOT NULL,
	`relationType` varchar(64) NOT NULL,
	`evidence` text,
	`createdAt` timestamp NOT NULL DEFAULT (now()),
	CONSTRAINT `entityRelationships_id` PRIMARY KEY(`id`)
);
--> statement-breakpoint
CREATE TABLE `reconEntities` (
	`id` varchar(32) NOT NULL,
	`runId` varchar(32) NOT NULL,
	`entityType` enum('domain','subdomain','ip','email','username','organization','url','certificate','asn','phone') NOT NULL,
	`value` varchar(1024) NOT NULL,
	`label` varchar(1024) NOT NULL,
	`confidence` int NOT NULL DEFAULT 70,
	`metadataJson` text,
	`createdAt` timestamp NOT NULL DEFAULT (now()),
	CONSTRAINT `reconEntities_id` PRIMARY KEY(`id`)
);
--> statement-breakpoint
CREATE TABLE `reconEvents` (
	`id` int AUTO_INCREMENT NOT NULL,
	`runId` varchar(32) NOT NULL,
	`moduleId` varchar(96) NOT NULL,
	`eventType` enum('queued','started','finding','completed','failed','notice') NOT NULL,
	`message` text NOT NULL,
	`payloadJson` text,
	`createdAt` timestamp NOT NULL DEFAULT (now()),
	CONSTRAINT `reconEvents_id` PRIMARY KEY(`id`)
);
--> statement-breakpoint
CREATE TABLE `reconRuns` (
	`id` varchar(32) NOT NULL,
	`userId` int NOT NULL,
	`target` varchar(512) NOT NULL,
	`targetType` enum('domain','ip','email','username','company','url','phone','asn') NOT NULL,
	`context` text,
	`status` enum('queued','running','completed','failed') NOT NULL DEFAULT 'queued',
	`riskScore` int NOT NULL DEFAULT 0,
	`riskLevel` enum('low','medium','high','critical') NOT NULL DEFAULT 'low',
	`summary` text,
	`resultsJson` text,
	`error` text,
	`startedAt` timestamp NOT NULL DEFAULT (now()),
	`completedAt` timestamp,
	CONSTRAINT `reconRuns_id` PRIMARY KEY(`id`)
);
--> statement-breakpoint
ALTER TABLE `analystSettings` ADD CONSTRAINT `analystSettings_userId_users_id_fk` FOREIGN KEY (`userId`) REFERENCES `users`(`id`) ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE `entityRelationships` ADD CONSTRAINT `entityRelationships_runId_reconRuns_id_fk` FOREIGN KEY (`runId`) REFERENCES `reconRuns`(`id`) ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE `entityRelationships` ADD CONSTRAINT `entityRelationships_sourceEntityId_reconEntities_id_fk` FOREIGN KEY (`sourceEntityId`) REFERENCES `reconEntities`(`id`) ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE `entityRelationships` ADD CONSTRAINT `entityRelationships_targetEntityId_reconEntities_id_fk` FOREIGN KEY (`targetEntityId`) REFERENCES `reconEntities`(`id`) ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE `reconEntities` ADD CONSTRAINT `reconEntities_runId_reconRuns_id_fk` FOREIGN KEY (`runId`) REFERENCES `reconRuns`(`id`) ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE `reconEvents` ADD CONSTRAINT `reconEvents_runId_reconRuns_id_fk` FOREIGN KEY (`runId`) REFERENCES `reconRuns`(`id`) ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE `reconRuns` ADD CONSTRAINT `reconRuns_userId_users_id_fk` FOREIGN KEY (`userId`) REFERENCES `users`(`id`) ON DELETE no action ON UPDATE no action;