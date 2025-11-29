import * as cdk from 'aws-cdk-lib';
import { Certificate, CertificateValidation } from 'aws-cdk-lib/aws-certificatemanager';
import {
  CacheHeaderBehavior,
  CachePolicy,
  CacheQueryStringBehavior,
  Distribution,
  HeadersFrameOption,
  HeadersReferrerPolicy,
  OriginAccessIdentity,
  PriceClass,
  ResponseHeadersPolicy,
  ViewerProtocolPolicy
} from 'aws-cdk-lib/aws-cloudfront';
import { S3BucketOrigin } from 'aws-cdk-lib/aws-cloudfront-origins';
import { BlockPublicAccess, Bucket } from 'aws-cdk-lib/aws-s3';
import { Construct } from 'constructs';

export class HostingStack extends cdk.Stack {
  constructor(scope: Construct, id: string, props?: cdk.StackProps) {
    super(scope, id, props);

    // S3 bucket for hosting the OAuth SPA
    const bucket = new Bucket(this, 'oauth-spa-bucket', {
      bucketName: 'oauth-spa-cals',
      versioned: true,
      blockPublicAccess: BlockPublicAccess.BLOCK_ALL, // Keep bucket private
      websiteIndexDocument: 'index.html',
      websiteErrorDocument: 'index.html', // SPA routing
    });

    // Create Origin Access Identity for CloudFront to access S3
    const originAccessIdentity = new OriginAccessIdentity(this, 'OAI', {
      comment: 'OAI for OAuth SPA',
    });

    // Grant CloudFront read access to the bucket
    bucket.grantRead(originAccessIdentity);

    // Create Cache Policy for SPA assets (JS, CSS, images)
    const assetsCachePolicy = new CachePolicy(this, 'AssetsCachePolicy', {
      cachePolicyName: 'oauth-spa-assets-cache',
      comment: 'Long-term caching for static assets (JS, CSS, images)',
      defaultTtl: cdk.Duration.days(30),
      maxTtl: cdk.Duration.days(365),
      minTtl: cdk.Duration.seconds(0),
      enableAcceptEncodingGzip: true,
      enableAcceptEncodingBrotli: true,
      headerBehavior: CacheHeaderBehavior.none(),
      queryStringBehavior: CacheQueryStringBehavior.none(),
    });

    // Create Response Headers Policy for security headers
    const responseHeadersPolicy = new ResponseHeadersPolicy(this, 'ResponseHeadersPolicy', {
      responseHeadersPolicyName: 'oauth-spa-headers',
      comment: 'Security headers for OAuth SPA',
      corsBehavior: {
        accessControlAllowOrigins: ['*'],
        accessControlAllowHeaders: ['*'],
        accessControlAllowMethods: ['GET', 'HEAD', 'OPTIONS'],
        accessControlAllowCredentials: false,
        accessControlMaxAge: cdk.Duration.hours(1),
        originOverride: true,
      },
      securityHeadersBehavior: {
        contentTypeOptions: { override: true },
        frameOptions: { frameOption: HeadersFrameOption.DENY, override: true },
        referrerPolicy: { referrerPolicy: HeadersReferrerPolicy.STRICT_ORIGIN_WHEN_CROSS_ORIGIN, override: true },
        strictTransportSecurity: {
          accessControlMaxAge: cdk.Duration.days(365),
          includeSubdomains: true,
          override: true,
        },
      },
    });

    // Create SSL certificate for custom domains (both prod and dev)
    const certificate = new Certificate(this, 'domain-certificate', {
      domainName: 'oauth.cals-api.com',
      subjectAlternativeNames: ['dev.oauth.cals-api.com'],
      validation: CertificateValidation.fromDns(),
    });

    // Create CloudFront distribution
    const distribution = new Distribution(this, 'oauth-spa-distribution', {
      defaultBehavior: {
        origin: S3BucketOrigin.withOriginAccessIdentity(bucket, {
          originAccessIdentity,
        }),
        viewerProtocolPolicy: ViewerProtocolPolicy.REDIRECT_TO_HTTPS,
        responseHeadersPolicy,
        cachePolicy: assetsCachePolicy,
        compress: true, // Enable gzip/brotli compression
      },
      defaultRootObject: 'index.html',
      // Handle SPA client-side routing by redirecting 404s to index.html
      errorResponses: [
        {
          httpStatus: 404,
          responseHttpStatus: 200,
          responsePagePath: '/index.html',
          ttl: cdk.Duration.minutes(5),
        },
        {
          httpStatus: 403,
          responseHttpStatus: 200,
          responsePagePath: '/index.html',
          ttl: cdk.Duration.minutes(5),
        },
      ],
      domainNames: ['oauth.cals-api.com', 'dev.oauth.cals-api.com'],
      certificate: certificate,
      priceClass: PriceClass.PRICE_CLASS_100, // US, Canada, Europe only
    });

    // Export bucket name and distribution ID for CI/CD
    new cdk.CfnOutput(this, 'BucketName', {
      value: bucket.bucketName,
      description: 'S3 bucket name for OAuth SPA',
      exportName: 'oauth-spa-bucket-name',
    });

    new cdk.CfnOutput(this, 'DistributionId', {
      value: distribution.distributionId,
      description: 'CloudFront distribution ID',
      exportName: 'oauth-spa-distribution-id',
    });

    new cdk.CfnOutput(this, 'DistributionDomainName', {
      value: distribution.distributionDomainName,
      description: 'CloudFront distribution domain name',
      exportName: 'oauth-spa-distribution-domain',
    });
  }
}
