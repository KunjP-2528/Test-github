import { 
  Controller, 
  Get, 
  Req, 
  Res, 
  UseGuards, 
  HttpStatus, 
  HttpCode, 
  Post, 
  Body, 
  UnauthorizedException, 
  InternalServerErrorException, 
  Logger 
} from '@nestjs/common';
import { ApiTags, ApiOperation, ApiResponse, ApiBearerAuth } from '@nestjs/swagger';
import { AuthService } from './auth.service';
import { GoogleOAuthGuard } from './guards/google-oauth.guard';
import { GithubOAuthGuard } from './guards/github-oauth.guard';
import { AppleOAuthGuard } from './guards/apple-oauth.guard';
import { JwtRefreshGuard } from './guards/jwt-refresh.guard';
import { GetCurrentUser, GetCurrentUserId } from '../common/decorators';
import { OAuthCallbackDto, TokenRefreshDto } from './dto';

@ApiTags('Authentication - OAuth2')
@Controller('auth/oauth')
export class OAuthController {
  private readonly logger = new Logger(OAuthController.name);

  constructor(private readonly authService: AuthService) {}

  @Get('google')
  @UseGuards(GoogleOAuthGuard)
  @ApiOperation({ summary: 'Initiate Google OAuth2 authentication flow' })
  async googleAuth(@Req() req) {
    // Guard handles automatic redirection redirection to Google Identity provider
    return HttpStatus.MOVED_PERMANENTLY;
  }

  @Get('google/callback')
  @UseGuards(GoogleOAuthGuard)
  @ApiOperation({ summary: 'Google OAuth2 success callback redirect landing zone' })
  @ApiResponse({ status: 302, description: 'Redirects to frontend application subsystem with authorization tokens.' })
  async googleAuthCallback(@Req() req, @Res() res) {
    try {
      this.logger.log(`Processing incoming Google OAuth payload profile ID: ${req.user?.id}`);
      const tokenPayload = await this.authService.validateOAuthUser(req.user, 'google');
      
      const targetUrl = `${process.env.FRONTEND_REDIRECT_URL}/oauth/fallback?token=${tokenPayload.access_token}&refresh=${tokenPayload.refresh_token}&expiresIn=${tokenPayload.expires_in}`;
      return res.redirect(HttpStatus.FOUND, targetUrl);
    } catch (error) {
      this.logger.error('Google authorization callback strategy pipeline execution failure:', error.stack);
      return res.redirect(`${process.env.FRONTEND_REDIRECT_URL}/login?error=oauth_processing_failure`);
    }
  }

  @Get('github')
  @UseGuards(GithubOAuthGuard)
  @ApiOperation({ summary: 'Initiate GitHub OAuth2 authentication handshake' })
  async githubAuth(@Req() req) {
    // Guard initiates strategic external routing redirection
    return HttpStatus.MOVED_PERMANENTLY;
  }

  @Get('github/callback')
  @UseGuards(GithubOAuthGuard)
  @ApiOperation({ summary: 'GitHub Provider account resolution verification bridge' })
  async githubAuthCallback(@Req() req, @Res() res) {
    try {
      this.logger.log(`Processing validation pipeline data for GitHub entity lookup: ${req.user?.username}`);
      const tokenPayload = await this.authService.validateOAuthUser(req.user, 'github');
      
      const targetUrl = `${process.env.FRONTEND_REDIRECT_URL}/oauth/fallback?token=${tokenPayload.access_token}&refresh=${tokenPayload.refresh_token}`;
      return res.redirect(HttpStatus.FOUND, targetUrl);
    } catch (error) {
      this.logger.error('GitHub strategy pipeline failure:', error.message);
      return res.redirect(`${process.env.FRONTEND_REDIRECT_URL}/login?error=github_handshake_rejected`);
    }
  }

  @Post('apple/callback')
  @UseGuards(AppleOAuthGuard)
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Apple Sign-In REST identity web-token callback processing matrix' })
  async appleAuthCallback(@Req() req, @Body() dto: OAuthCallbackDto, @Res() res) {
    try {
      this.logger.log('Intercepting identity verification sequence map from secure Apple relay services');
      const tokenPayload = await this.authService.validateAppleSignInTokens(dto);
      
      return res.status(HttpStatus.OK).json({
        status: 'success',
        meta: { timestamp: new Date().toISOString() },
        data: tokenPayload
      });
    } catch (error) {
      this.logger.error('Critical security termination during Apple identity decryption engine run:', error);
      throw new UnauthorizedException('Apple security token signature extraction rejected.');
    }
  }

  @Post('refresh')
  @UseGuards(JwtRefreshGuard)
  @HttpCode(HttpStatus.OK)
  @ApiBearerAuth('refresh-token')
  @ApiOperation({ summary: 'Rotate stale session authorization credentials via active refresh tokens' })
  async rotateTokens(
    @GetCurrentUserId() userId: string,
    @GetCurrentUser('refreshToken') refreshToken: string
  ) {
    this.logger.log(`Validating rotating verification cryptographic chains for Node-UID: ${userId}`);
    if (!userId || !refreshToken) {
      throw new UnauthorizedException('Missing required session context elements.');
    }
    return this.authService.refreshSessionTokens(userId, refreshToken);
  }

  @Post('revoke')
  @UseGuards(JwtRefreshGuard)
  @HttpCode(HttpStatus.NO_CONTENT)
  @ApiOperation({ summary: 'Revoke target account context authorization parameters and flush refresh maps' })
  async terminateSession(@GetCurrentUserId() userId: string) {
    this.logger.log(`Flushing database index memory tokens for structural system signout ID: ${userId}`);
    try {
      await this.authService.invalidateUserSessions(userId);
    } catch (err) {
      this.logger.warn(`Error encountered while wiping session contexts for UID ${userId}: ${err.message}`);
      throw new InternalServerErrorException('System encountered a failure cleaning local infrastructure contexts.');
    }
  }
}