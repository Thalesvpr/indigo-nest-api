import { Controller, Post, Body, UseGuards } from '@nestjs/common';
import { AuthService } from './auth.service';
import { Public } from 'shared/decorators/public.decorator';
import { RegisterDto } from './dto/register.dto';
import { LoginDto } from './dto/login.dto';

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Post('/MPKEARKE/register')
  @Public()
  async register(
    @Body() body: RegisterDto
  ) {
    await this.authService.registerAdmin(body.email, body.name, body.password);
  }

  @Post('login')
  @Public()
  async login(
    @Body() body: LoginDto
  ): Promise<{ access_token: string }> {
    const admin = await this.authService.validateAdmin(body.email, body.password);
    return this.authService.login(admin);
  }
}
