import { IsString, IsEmail } from 'class-validator';

export class RegisterDto {
  @IsString({ message: 'Name must be a string' })
  name: string;

  @IsEmail({}, { message: 'Invalid email address' })
  email: string;

  @IsString({ message: 'Password must be a string' })
  password: string;
}
