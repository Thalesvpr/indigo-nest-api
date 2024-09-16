import { IsString, IsEmail } from 'class-validator';

export class LoginDto {
  @IsEmail({}, { message: 'Invalid email address' })
  email: string;

  @IsString({ message: 'Password must be a string' })
  password: string;
}
